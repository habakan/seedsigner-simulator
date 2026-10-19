"""bitwasm firmware: the review and the signature come from signer.wasm.

habakan/seedsigner keeps embit's PSBTParser for the screens but signs only with
bitwasm-signer's signer.wasm, after its own review of the same bytes agrees with
embit's. Here the modules run on the page's WebAssembly engine (browser_wasm.py)
instead of WAMR, and this drives that through the device's own screens:

  1. a testnet P2WPKH spend with change, carrying non_witness_utxo as signer.wasm
     requires, is reviewed and signed, and the signature has to be byte-identical
     to embit's -- both use RFC6979, so any difference is a bug in one of them;
  2. the same spend from a legacy P2PKH input, which signer.wasm does not sign,
     has to stop on the refusal screen rather than reach the approve screen.

    SIM_FIRMWARE=bitwasm python3 test/test_bitwasm.py
"""

import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness
from harness import Log, check, report
from test_cards_browser import press
from test_mainnet import READ_SCREEN_QR, collect_animated_qr, load_reel, wait_screen

import make_qr_y4m

from playwright.sync_api import sync_playwright

WALLET_ZIP = harness.find_asset("wallet-bitwasm.zip")
REEL = harness.artifact("mainnet-camera.y4m")
SEED_REEL = harness.artifact("qr.y4m")
SEND_SATS, FEE_SATS, INPUT_SATS = 60_000, 1_000, 100_000


def build_psbts():
    """(the P2WPKH spend, the same spend from P2PKH, the signatures embit makes)."""
    from embit import bip32, bip39, script
    from embit.networks import NETWORKS
    from embit.psbt import PSBT, DerivationPath
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(make_qr_y4m.MNEMONIC),
                                 version=NETWORKS["test"]["xprv"])
    paths = {"in": "m/84h/1h/0h/0/0", "change": "m/84h/1h/0h/1/0", "legacy": "m/44h/1h/0h/0/0"}
    keys = {k: root.derive(p) for k, p in paths.items()}

    recipient = script.Script(b"\x00\x14" + bytes(range(20)))

    def psbt(spent):
        prev = Transaction(vin=[TransactionInput(b"\x11" * 32, 0)], vout=[
            TransactionOutput(INPUT_SATS, (script.p2wpkh if spent == "in" else script.p2pkh)(keys[spent]))])
        tx = Transaction(vin=[TransactionInput(prev.txid(), 0)], vout=[
            TransactionOutput(SEND_SATS, recipient),
            TransactionOutput(INPUT_SATS - SEND_SATS - FEE_SATS, script.p2wpkh(keys["change"])),
        ])
        p = PSBT(tx)
        p.inputs[0].non_witness_utxo = prev
        if spent == "in":
            p.inputs[0].witness_utxo = prev.vout[0]
        p.inputs[0].bip32_derivations[keys[spent].key.get_public_key()] = DerivationPath(
            root.my_fingerprint, bip32.parse_path(paths[spent]))
        p.outputs[1].bip32_derivations[keys["change"].key.get_public_key()] = DerivationPath(
            root.my_fingerprint, bip32.parse_path(paths["change"]))
        return p

    segwit = psbt("in")
    reference = PSBT.parse(segwit.serialize())
    reference.sign_with(root)
    return segwit.serialize(), psbt("legacy").serialize(), dict(reference.inputs[0].partial_sigs)


def write_reel(payload):
    make_qr_y4m.write_y4m(REEL + ".next", payload)
    os.replace(REEL + ".next", REEL)


def walk_review(page, log, window):
    """Enter through the review screens until the approve screen; the names seen."""
    seen = []
    while True:
        mark = log.mark()
        press(page, "Enter")
        name = log.wait(r"display\(\) enter: (\w+)", 90, "the next review screen", mark).group(1)
        seen.append(name)
        if name in ("PSBTFinalizeScreen", "DireWarningScreen") or len(seen) > 10:
            return seen


def main() -> int:
    if not WALLET_ZIP:
        print("no wallet-bitwasm.zip: run build/build-wallet-zip.sh bitwasm first", file=sys.stderr)
        return 2
    sys.path.append(WALLET_ZIP)
    full, legacy, expected_sigs = build_psbts()
    unpacked = make_qr_y4m.vendored_libraries(WALLET_ZIP)
    make_qr_y4m.write_y4m(SEED_REEL, make_qr_y4m.SEEDQR)
    load_reel(SEED_REEL)

    with sync_playwright() as p:
        browser = p.chromium.launch(args=[
            "--use-fake-ui-for-media-stream",
            "--use-fake-device-for-media-stream",
            f"--use-file-for-fake-video-capture={REEL}",
        ])
        context = browser.new_context(permissions=["camera"], viewport={"width": 900, "height": 1000})
        page = context.new_page()
        log = Log(page)
        page.goto(harness.wallet_url(firmware="bitwasm"))
        log.wait(r"display\(\) enter: MainMenuScreen", 300, "the wallet to boot")
        page.add_script_tag(url="jsQR.js")

        print("scanning the published test seed")
        window = log.mark()
        press(page, "Enter")
        window = wait_screen(log, "SeedFinalizeScreen", window, "the scanned seed", timeout=240)
        press(page, "Enter")
        window = wait_screen(log, "SeedOptionsScreen", window, "the seed's own menu")

        print("\nscanning a P2WPKH spend with change")
        write_reel(base64.b64encode(full).decode())
        press(page, "Enter")            # Scan PSBT, first of the seed's options
        window = wait_screen(log, "PSBTOverviewScreen", window, "the overview", timeout=240)
        harness.save_screen(page, harness.artifact("bitwasm-overview.png"))
        check("signer.wasm's review agrees with embit's and the overview is shown",
              log.seen(r"PSBTBitwasm\w+View", window) is None)

        seen = walk_review(page, log, window)
        print("  review screens: " + " -> ".join(seen))
        check("the review reaches the approve screen", seen[-1] == "PSBTFinalizeScreen", seen[-1])

        signing = log.mark()
        press(page, "Enter")            # Approve
        wait_screen(log, "QRDisplayScreen", signing, "the signed PSBT", timeout=240)
        check("signing raised nothing", log.seen(r"SystemError|Traceback|RAISED", signing) is None)
        harness.save_screen(page, harness.artifact("bitwasm-signed.png"))

        signed, frames = collect_animated_qr(page)
        check("the signed PSBT comes back off the screen", signed is not None, f"{len(frames)} frames")
        if signed:
            from embit.psbt import PSBT
            sigs = dict(PSBT.parse(signed).inputs[0].partial_sigs)
            check("signer.wasm's signature is byte-identical to embit's", sigs == expected_sigs,
                  f"{ {k.sec().hex()[:8]: v.hex() for k, v in sigs.items()} }")

        print("\nscanning the same spend from a legacy P2PKH input")
        window = log.mark()
        page.wait_for_timeout(1600)
        press(page, "Enter")            # leave the QR screen
        window = wait_screen(log, "MainMenuScreen", window, "home")
        write_reel(base64.b64encode(legacy).decode())
        press(page, "Enter")            # Scan
        window = wait_screen(log, "ButtonListScreen", window, "the signer list", timeout=240)
        press(page, "Enter")            # the seed already loaded
        log.wait(r"View\.run enter: PSBTBitwasmRefusedView", 180, "the refusal", window)
        harness.save_screen(page, harness.artifact("bitwasm-refused.png"))
        check("signer.wasm refuses it and the device says so", True)
        browser.close()

    import shutil
    shutil.rmtree(unpacked, ignore_errors=True)
    return report()


if __name__ == "__main__":
    sys.exit(main())
