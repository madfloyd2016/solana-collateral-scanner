import json
import tempfile
import unittest
from pathlib import Path

import identity_dataflow


class IdentityDataflowTests(unittest.TestCase):
    def analyze(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.rs"
            path.write_text(source, encoding="utf-8")
            return identity_dataflow.analyze_rust_file(path)

    def test_guarded_asset_identity_and_valuation_flow(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let source_mint = ctx.accounts.user_token_account.mint;
            let market = ctx.accounts.market;
            let config_mint = market.collateral_mint;
            let decimals = market.collateral_decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            validate_identity(source_mint, config_mint);
            update_borrow_capacity(value);
            Ok(())
        }
        fn validate_identity(actual_mint: Pubkey, expected_mint: Pubkey) -> Result<()> {
            require_keys_eq!(actual_mint, expected_mint);
            Ok(())
        }
        '''
        findings = self.analyze(source)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["dataflow_status"], "binding_guard_and_config_value_flow_observed_manual_validation_required")
        flows = finding["evidence"]["flows"]
        self.assertTrue(flows["actual_mint_seen"])
        self.assertTrue(flows["config_mint_seen"])
        self.assertTrue(flows["mint_binding_guard_observed"])
        self.assertTrue(flows["config_to_value_sink"])
        self.assertTrue(flows["amount_to_sink"])
        self.assertTrue(flows["oracle_value_to_sink"])
        self.assertTrue(flows["decimals_to_sink"])

    def test_missing_identity_guard_is_flagged_as_review_lead_not_confirmed_bug(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let source_mint = ctx.accounts.user_token_account.mint;
            let market = ctx.accounts.market;
            let config_mint = market.collateral_mint;
            let decimals = market.collateral_decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertEqual(finding["dataflow_status"], "potential_unbound_mint_to_config_value_flow_review_required")
        self.assertEqual(finding["review_priority"], "HIGH_REVIEW")
        self.assertIn("not proof", finding["limitations"])

    def test_helper_argument_propagation_finds_guard_in_helper(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let source = ctx.accounts.user_token_account;
            let market = ctx.accounts.market;
            check_identity(source, market)?;
            let value = calculate_value(amount, market.decimals, read_oracle_price(ctx.accounts.oracle)?);
            update_borrow_capacity(value);
            Ok(())
        }
        fn check_identity(source: Account<TokenAccount>, market: Account<Market>) -> Result<()> {
            let actual = source.mint;
            let expected = market.collateral_mint;
            require_keys_eq!(actual, expected);
            Ok(())
        }
        fn calculate_value(amount: u64, decimals: u8, price: u64) -> Result<u64> {
            let value = amount * price / 10u64.pow(decimals as u32);
            Ok(value)
        }
        '''
        finding = self.analyze(source)[0]
        self.assertEqual(finding["dataflow_status"], "binding_guard_and_config_value_flow_observed_manual_validation_required")
        self.assertTrue(finding["evidence"]["helper_edges"])
        self.assertTrue(any(g["function"] == "check_identity" for g in finding["evidence"]["guards"]))
        self.assertTrue(finding["evidence"]["flows"]["decimals_to_sink"])

    def test_helper_return_summary_reaches_valuation_sink(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let price = load_price(ctx.accounts.oracle)?;
            let decimals = ctx.accounts.market.decimals;
            let value = calculate_value(amount, price, decimals)?;
            update_borrow_capacity(value);
            Ok(())
        }
        fn load_price(oracle: AccountInfo) -> Result<u64> {
            let price = oracle.price;
            Ok(price)
        }
        fn calculate_value(amount: u64, price: u64, decimals: u8) -> Result<u64> {
            let computed = amount * price / 10u64.pow(decimals as u32);
            Ok(computed)
        }
        '''
        finding = self.analyze(source)[0]
        sink = next(s for s in finding["evidence"]["sinks"] if s["callee"] == "update_borrow_capacity")
        self.assertIn("amount_input", sink["taint_categories"])
        self.assertIn("oracle_value", sink["taint_categories"])
        self.assertIn("config_decimals", sink["taint_categories"])

    def test_anchor_context_direct_mint_equality_is_reported(self):
        source = '''
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            #[account(constraint = user_token_account.mint == market.collateral_mint)]
            pub user_token_account: Account<'info, TokenAccount>,
            pub market: Account<'info, Market>,
        }
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let market = ctx.accounts.market;
            let config_mint = market.collateral_mint;
            let decimals = market.decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertTrue(finding["evidence"]["flows"]["mint_binding_guard_observed"])
        self.assertTrue(any(g["kind"] == "anchor_context_mint_equality_pattern" for g in finding["evidence"]["guards"]))

    def test_direct_account_field_comparison_is_recognized(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let source = ctx.accounts.user_token_account;
            let market = ctx.accounts.market;
            validate_identity(source, market)?;
            let decimals = market.decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        fn validate_identity(source: Account<TokenAccount>, market: Account<Market>) -> Result<()> {
            require_keys_eq!(source.mint, market.collateral_mint);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertTrue(finding["evidence"]["flows"]["mint_binding_guard_observed"])

    def test_max_depth_limits_helper_guard_visibility(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let source = ctx.accounts.user_token_account;
            let market = ctx.accounts.market;
            validate_identity(source, market)?;
            let decimals = market.decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        fn validate_identity(source: Account<TokenAccount>, market: Account<Market>) -> Result<()> {
            let actual_mint = source.mint;
            let expected_mint = market.collateral_mint;
            require_keys_eq!(actual_mint, expected_mint);
            Ok(())
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "depth.rs"
            path.write_text(source, encoding="utf-8")
            shallow = identity_dataflow.analyze_rust_file(path, max_depth=0)[0]
            deep = identity_dataflow.analyze_rust_file(path, max_depth=2)[0]
        self.assertFalse(shallow["evidence"]["flows"]["mint_binding_guard_observed"])
        self.assertTrue(deep["evidence"]["flows"]["mint_binding_guard_observed"])

    def test_synthetic_regression_fixtures_distinguish_guarded_and_unbound(self):
        sample_dir = Path(__file__).parents[1] / "sample"
        guarded = identity_dataflow.analyze_rust_file(sample_dir / "identity_flow_guarded.rs")
        unbound = identity_dataflow.analyze_rust_file(sample_dir / "identity_flow_unbound.rs")
        self.assertEqual(guarded[0]["dataflow_status"], "binding_guard_and_config_value_flow_observed_manual_validation_required")
        self.assertEqual(unbound[0]["dataflow_status"], "potential_unbound_mint_to_config_value_flow_review_required")

    def test_anchor_context_oracle_equality_is_reported(self):
        source = '''
        #[derive(Accounts)]
        pub struct Borrow<'info> {
            #[account(constraint = oracle.key() == bank.primary_oracle)]
            pub oracle: AccountInfo<'info>,
            pub bank: Account<'info, Bank>,
        }
        pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
            let bank = ctx.accounts.bank;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let decimals = bank.decimals;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertTrue(finding["evidence"]["flows"]["oracle_binding_guard_observed"])
        self.assertTrue(any(g["kind"] == "anchor_context_oracle_equality_pattern" for g in finding["evidence"]["guards"]))

    def test_unrelated_mint_comparison_does_not_count_as_identity_guard(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let source_mint = ctx.accounts.user_token_account.mint;
            let market = ctx.accounts.market;
            let config_mint = market.collateral_mint;
            let decimals = market.decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            require_keys_eq!(admin_mint, fee_mint);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertEqual(finding["dataflow_status"], "potential_unbound_mint_to_config_value_flow_review_required")
        self.assertFalse(finding["evidence"]["flows"]["mint_binding_guard_observed"])

    def test_oracle_account_to_bank_primary_oracle_guard(self):
        source = '''
        pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
            let bank = ctx.accounts.bank;
            let oracle = ctx.accounts.oracle;
            validate_oracle(oracle, bank)?;
            let price = read_oracle_price(oracle)?;
            let decimals = bank.decimals;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        fn validate_oracle(oracle: AccountInfo, bank: Account<Bank>) -> Result<()> {
            require_keys_eq!(oracle.key(), bank.primary_oracle);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertTrue(finding["evidence"]["flows"]["oracle_binding_guard_observed"])
        self.assertTrue(any(g["kind"] == "oracle_account_to_config_oracle_comparison" for g in finding["evidence"]["guards"]))

    def test_comment_and_string_do_not_create_fake_guard(self):
        source = r'''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            // require_keys_eq!(source_mint, config_mint);
            let note = "source_mint == config_mint";
            let source_mint = ctx.accounts.user_token_account.mint;
            let market = ctx.accounts.market;
            let config_mint = market.collateral_mint;
            let decimals = market.decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertFalse(finding["evidence"]["flows"]["mint_binding_guard_observed"])

    def test_insufficient_evidence_is_not_labeled_unbound(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            token::transfer_checked();
            update_borrow_capacity(amount);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertEqual(finding["dataflow_status"], "insufficient_identity_dataflow_evidence")
        self.assertNotEqual(finding["review_priority"], "HIGH_REVIEW")

    def test_yDelta_style_review_pattern_is_a_negative_regression_reference(self):
        # Synthetic pattern based on the user's manual review notes. This is
        # not yDelta's source and does not independently validate its program.
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let source_mint = ctx.accounts.user_token_account.mint;
            let market = ctx.accounts.market;
            let config_mint = market.collateral_mint;
            require_keys_eq!(source_mint, config_mint);
            let decimals = market.collateral_mint_decimals;
            let price = read_oracle_price(ctx.accounts.bank.primary_oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        finding = self.analyze(source)[0]
        self.assertEqual(finding["dataflow_status"], "binding_guard_and_config_value_flow_observed_manual_validation_required")
        self.assertFalse(finding["dataflow_status"].startswith("potential_unbound"))

    def test_cross_instruction_state_field_map_links_market_writes_and_reads(self):
        source = '''
        pub struct Market {
            pub collateral_mint: Pubkey,
            pub primary_oracle: Pubkey,
            pub collateral_mint_decimals: u8,
        }
        #[derive(Accounts)]
        pub struct CreateMarket<'info> {
            pub market: Account<'info, Market>,
        }
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            pub market: Account<'info, Market>,
        }
        #[derive(Accounts)]
        pub struct Borrow<'info> {
            pub market: Account<'info, Market>,
        }
        pub fn create_market(ctx: Context<CreateMarket>, mint: Pubkey, oracle: Pubkey) -> Result<()> {
            let market = Market {
                collateral_mint: mint,
                primary_oracle: oracle,
                collateral_mint_decimals: 9,
            };
            Ok(())
        }
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let market = ctx.accounts.market;
            let mint = market.collateral_mint;
            let decimals = market.collateral_mint_decimals;
            Ok(())
        }
        pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
            let market = ctx.accounts.market;
            let oracle = market.primary_oracle;
            let price = read_oracle_price(oracle)?;
            update_borrow_capacity(price * amount);
            Ok(())
        }
        '''
        finding = next(item for item in self.analyze(source) if item["function"] == "borrow")
        links = finding["evidence"]["cross_instruction_state_field_links"]
        fields = {(item["struct_type"], item["field"]) for item in links}
        self.assertIn(("Market", "collateral_mint"), fields)
        self.assertIn(("Market", "primary_oracle"), fields)
        self.assertIn(("Market", "collateral_mint_decimals"), fields)
        self.assertTrue(all(item["cross_instruction_candidate"] for item in links))

    def test_report_writer_emits_json_csv_and_review_pack(self):
        source = '''
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let source_mint = ctx.accounts.user_token_account.mint;
            let market = ctx.accounts.market;
            let config_mint = market.collateral_mint;
            let decimals = market.decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            require_keys_eq!(source_mint, config_mint);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        findings = self.analyze(source)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            identity_dataflow.write_reports(findings, out)
            payload = json.loads((out / "identity_dataflow.json").read_text())
            self.assertEqual(len(payload), 1)
            self.assertTrue((out / "identity_dataflow.csv").exists())
            self.assertEqual(len(list((out / "identity_dataflow_review").glob("*.md"))), 1)


if __name__ == "__main__":
    unittest.main()
