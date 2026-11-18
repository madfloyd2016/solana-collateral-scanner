import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import io
import zlib

import scanner


class ScannerTests(unittest.TestCase):
    def test_comment_and_string_braces_do_not_break_function_extraction(self):
        source = r'''
        pub fn deposit(asset_id: u16) -> Result<()> {
            let s = "{ not a block }";
            /* } nested-ish */
            helper(asset_id);
            Ok(())
        }
        fn helper(asset_id: u16) { let _x = asset_id; }
        '''
        functions = scanner.extract_functions(source, Path("fixture.rs"))
        self.assertEqual([f["name"] for f in functions], ["deposit", "helper"])

    def test_cross_function_signals_are_aggregated(self):
        source = '''
        pub fn deposit_collateral(asset_id: u16) -> Result<()> {
            transfer_in();
            calculate_value(asset_id)
        }
        fn transfer_in() { token::transfer_checked(); }
        fn calculate_value(asset_id: u16) {
            let decimals = config.decimals;
            let price = read_oracle_price();
            update_collateral_value(price);
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.rs"
            path.write_text(source)
            findings = scanner.scan_rust(path)
        self.assertTrue(findings)
        root = next(item for item in findings if item["function"] == "deposit_collateral")
        self.assertIn("token_transfer", root["signals"])
        self.assertIn("oracle_price", root["signals"])
        self.assertIn("decimals_scale", root["signals"])

    def test_anchor_context_constraints_are_attached_to_handler(self):
        source = '''
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            #[account(has_one = mint)]
            pub collateral_config: Account<'info, Config>,
            pub mint: Account<'info, Mint>,
        }
        pub fn deposit(ctx: Context<Deposit>, asset_id: u16) -> Result<()> {
            token::transfer_checked();
            read_oracle_price();
            Ok(())
        }
        '''
        functions = scanner.extract_functions(source, Path("anchor.rs"))
        handler = next(fn for fn in functions if fn["name"] == "deposit")
        self.assertEqual(handler["context_name"], "Deposit")
        self.assertIn("has_one", handler["context_clean"])
        _, by_name = scanner.build_call_graph(functions)
        finding = scanner.analyze_function(handler, by_name)
        self.assertIsNotNone(finding)
        self.assertIn("mint_binding_check", finding["signals"])

    def test_codama_idl_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "codama.idl.json"
            path.write_text(json.dumps({"kind": "rootNode", "program": {"instructions": [{
                "name": "depositCollateral",
                "accounts": [{"name": "collateralMint"}, {"name": "oracle"}, {"name": "vaultTokenAccount"}],
                "arguments": [{"name": "assetId"}]
            }]}}))
            findings = scanner.scan_idl(path)
        self.assertEqual(len(findings), 1)
        self.assertIn("mint", findings[0]["signals"])
        self.assertIn("oracle", findings[0]["signals"])

    def test_anchor_idl_nested_accounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.idl.json"
            path.write_text(json.dumps({"instructions": [{
                "name": "deposit_collateral",
                "accounts": [{"name": "user", "accounts": [
                    {"name": "collateral_mint"}, {"name": "oracle_account"},
                    {"name": "vault_token_account"}
                ]}],
                "args": [{"name": "asset_id"}]
            }]}))
            findings = scanner.scan_idl(path)
        self.assertEqual(len(findings), 1)
        self.assertIn("mint", findings[0]["signals"])
        self.assertIn("oracle", findings[0]["signals"])

    def test_legacy_anchor_idl_decode(self):
        idl = {"version": "0.1.0", "instructions": []}
        compressed = zlib.compress(json.dumps(idl).encode())
        raw = b"12345678" + bytes(32) + len(compressed).to_bytes(4, "little") + compressed
        self.assertEqual(scanner.decode_anchor_idl(raw), idl)

    def test_legacy_anchor_idl_address_is_pubkey_sized(self):
        address = scanner.anchor_legacy_idl_address("11111111111111111111111111111111")
        self.assertEqual(len(scanner.b58decode(address)), 32)

    def test_idl_explorer_accepts_codama_content(self):
        payload = {"type": "pmp", "content": json.dumps({
            "kind": "rootNode", "program": {"instructions": [{"name": "borrow", "accounts": [], "arguments": []}]}
        }), "address": "metadata-address", "authority": "authority"}
        class FakeResponse(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()
        with patch("scanner.urllib.request.urlopen", return_value=FakeResponse(json.dumps(payload).encode())):
            idl, meta = scanner.fetch_idl_explorer("11111111111111111111111111111111")
        self.assertEqual(idl["kind"], "rootNode")
        self.assertEqual(meta["idl_provider"], "pmp")

    def test_base58_round_trip(self):
        raw = bytes(range(32))
        self.assertEqual(scanner.b58decode(scanner.b58encode(raw)), raw)

    def test_synthetic_fixture_is_flagged(self):
        path = Path(__file__).parents[1] / "sample" / "loopscale_like.rs"
        findings = scanner.scan_rust(path)
        self.assertTrue(any(item["priority"] in {"HIGH_REVIEW", "MEDIUM_REVIEW"} for item in findings))

    def test_identity_assessment_does_not_call_pattern_presence_a_security_verdict(self):
        source = """
        pub fn deposit_collateral(asset_id: u16) -> Result<()> {
            let selected_asset_config = asset_config(asset_id);
            require_keys_eq!(user_mint.key(), market_mint.key());
            require_keys_eq!(oracle.key(), bank.primary_oracle);
            token::transfer_checked();
            read_oracle_price();
            let decimals = mint.decimals;
            let collateral_value = price * amount;
            update_borrow_capacity(collateral_value);
            Ok(())
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guarded.rs"
            path.write_text(source)
            findings = scanner.scan_rust(path)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["identity_assessment"], "binding_patterns_present_manual_validation_required")
        self.assertIn("does not prove", findings[0]["assessment_limit"])


if __name__ == "__main__":
    unittest.main()
