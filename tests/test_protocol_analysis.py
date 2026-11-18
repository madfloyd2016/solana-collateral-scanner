import tempfile
import unittest
from pathlib import Path

import protocol_analysis
import identity_dataflow
import scanner


class ProtocolAnalysisTests(unittest.TestCase):
    def analyze_protocol(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "protocol.rs"
            path.write_text(source, encoding="utf-8")
            return protocol_analysis.analyze_rust_file(path)

    def analyze_dataflow(self, source, max_depth=3):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "protocol.rs"
            path.write_text(source, encoding="utf-8")
            return identity_dataflow.analyze_rust_file(path, max_depth=max_depth)

    def test_anchor_token_mint_plus_has_one_is_structured_identity_guard(self):
        source = '''
        use anchor_lang::prelude::*;
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            #[account(mut, token::mint = collateral_mint)]
            pub user_token_account: Account<'info, TokenAccount>,
            #[account(has_one = collateral_mint)]
            pub market: Account<'info, Market>,
            pub collateral_mint: Account<'info, Mint>,
        }
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let market = ctx.accounts.market;
            let decimals = market.collateral_decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        contexts = protocol_analysis.parse_anchor_accounts(source)
        self.assertIn("Deposit", contexts)
        self.assertTrue(contexts["Deposit"]["mint_guard"])
        findings = self.analyze_dataflow(source)
        deposit = next(item for item in findings if item["function"] == "deposit")
        self.assertTrue(deposit["evidence"]["flows"]["mint_binding_guard_observed"])
        self.assertTrue(any(g["kind"] == "anchor_accounts_struct_mint_identity_chain" for g in deposit["evidence"]["guards"]))

    def test_anchor_oracle_has_one_is_structured_guard(self):
        source = '''
        #[derive(Accounts)]
        pub struct Borrow<'info> {
            #[account(has_one = primary_oracle)]
            pub bank: Account<'info, Bank>,
            pub primary_oracle: AccountInfo<'info>,
        }
        pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
            let bank = ctx.accounts.bank;
            let price = read_oracle_price(ctx.accounts.primary_oracle)?;
            let value = amount * price;
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        contexts = protocol_analysis.parse_anchor_accounts(source)
        self.assertTrue(contexts["Borrow"]["oracle_guard"])
        finding = next(item for item in self.analyze_dataflow(source) if item["function"] == "borrow")
        self.assertTrue(finding["evidence"]["flows"]["oracle_binding_guard_observed"])


    def test_anchor_pda_seeds_bump_and_owner_are_recorded(self):
        source = '''
        #[derive(Accounts)]
        pub struct LoadMarket<'info> {
            #[account(seeds = [b"market", authority.key().as_ref()], bump, owner = program_id)]
            pub market: Account<'info, Market>,
            pub authority: Signer<'info>,
        }
        '''
        field = protocol_analysis.parse_anchor_accounts(source)["LoadMarket"]["fields"][0]
        self.assertTrue(field["pda_bump"])
        self.assertTrue(field["pda_seeds"])
        self.assertIn('b"market"', field["pda_seeds"][0])
        self.assertEqual(field["owner_constraints"], ["program_id"])


    def test_unbound_anchor_mint_account_is_only_low_severity_hygiene_lead(self):
        source = '''
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            pub market: Account<'info, Market>,
            pub mint: Account<'info, Mint>,
            pub source_token_account: Account<'info, TokenAccount>,
        }
        '''
        findings = self.analyze_protocol(source)
        item = next(item for item in findings if item["analysis_type"] == "anchor_unchecked_mint_account_key_review")
        self.assertEqual(item["priority"], "LOW_REVIEW")
        self.assertIn("mint", item["fields"])


    def test_anchor_context_with_instruction_attribute_is_parsed(self):
        source = '''
        #[derive(Accounts)]
        #[instruction(amount: u64)]
        pub struct Deposit<'info> {
            #[account(token::mint = mint)]
            pub source_token_account: Account<'info, TokenAccount>,
            #[account(has_one = mint)]
            pub market: Account<'info, Market>,
            pub mint: Account<'info, Mint>,
        }
        '''
        context = protocol_analysis.parse_anchor_accounts(source)["Deposit"]
        self.assertTrue(context["mint_guard"])

    def test_unchecked_multiplication_and_literal_subtraction_are_reported(self):
        source = '''
        pub fn update_collateral_value(amount: u64, price: u64, balance: u64) -> Result<()> {
            let value = amount * price;
            let remaining = balance - 1u64;
            Ok(())
        }
        '''
        findings = self.analyze_protocol(source)
        operations = {item["operation"] for item in findings if item["analysis_type"] == "financial_arithmetic_review"}
        self.assertIn("unchecked_multiplication", operations)
        self.assertIn("unchecked_subtraction", operations)

    def test_checked_subtraction_with_unwrap_fallback_is_flagged_for_semantics_review(self):
        source = '''
        pub fn update_available_balance(balance: u64, amount: u64) -> Result<u64> {
            let next = balance.checked_sub(amount).unwrap_or(0);
            Ok(next)
        }
        '''
        findings = self.analyze_protocol(source)
        item = next(item for item in findings if item.get("operation") == "checked_sub")
        self.assertEqual(item["status"], "checked_arithmetic_fallback_semantics_review")

    def test_anchor_direct_constraint_is_recognized(self):
        source = '''
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            #[account(constraint = user_token_account.mint == market.collateral_mint)]
            pub user_token_account: Account<'info, TokenAccount>,
            pub market: Account<'info, Market>,
        }
        '''
        context = protocol_analysis.parse_anchor_accounts(source)["Deposit"]
        self.assertTrue(context["mint_guard"])

    def test_token_2022_extension_with_rejection_policy_is_not_labeled_exposed(self):
        source = '''
        pub fn validate_mint_extensions(mint: AccountInfo) -> Result<()> {
            let ext = ExtensionType::PermanentDelegate;
            if ext == ExtensionType::PermanentDelegate {
                return Err(ErrorCode::UnsupportedTokenExtension.into());
            }
            Ok(())
        }
        '''
        findings = self.analyze_protocol(source)
        item = next(item for item in findings if item["analysis_type"] == "token_2022_extension_policy")
        self.assertEqual(item["status"], "extension_rejection_or_allowlist_logic_observed")
        self.assertIn("PermanentDelegate", item["extensions"])

    def test_token_2022_extension_without_policy_is_review_lead(self):
        source = '''
        pub fn inspect_mint(mint: AccountInfo) -> Result<()> {
            let ext = ExtensionType::TransferHook;
            msg!("checking extension");
            Ok(())
        }
        '''
        findings = self.analyze_protocol(source)
        item = next(item for item in findings if item["analysis_type"] == "token_2022_extension_policy")
        self.assertEqual(item["status"], "extension_present_policy_not_obvious")
        self.assertEqual(item["priority"], "MEDIUM_REVIEW")

    def test_unchecked_financial_subtraction_is_reported(self):
        source = '''
        fn post_transfer_vault_balance_liquidity_reserve_checks(
            initial_vault_balance: u64,
            initial_available: u64,
        ) -> Result<()> {
            let slack = initial_vault_balance - initial_available;
            Ok(())
        }
        '''
        findings = self.analyze_protocol(source)
        item = next(item for item in findings if item["analysis_type"] == "financial_arithmetic_review")
        self.assertEqual(item["operation"], "unchecked_subtraction")
        self.assertEqual(item["priority"], "HIGH_REVIEW")
        dataflow = self.analyze_dataflow(source)
        self.assertTrue(any(item["function"].endswith("_checks") for item in dataflow))

    def test_checked_subtraction_is_recorded_as_checked_not_unchecked(self):
        source = '''
        fn update_available_balance(vault_balance: u64, available: u64) -> Result<u64> {
            let slack = vault_balance.checked_sub(available).ok_or(ErrorCode::MathOverflow)?;
            Ok(slack)
        }
        '''
        findings = self.analyze_protocol(source)
        item = next(item for item in findings if item["analysis_type"] == "financial_arithmetic_review")
        self.assertEqual(item["status"], "checked_arithmetic_observed_manual_semantics_review")

    def test_flash_repay_gets_dedicated_coverage_finding(self):
        source = '''
        pub fn flash_repay(ctx: Context<FlashRepay>, amount: u64) -> Result<()> {
            let accounts = ctx.remaining_accounts;
            transfer_checked(accounts, amount)?;
            Ok(())
        }
        '''
        findings = self.analyze_protocol(source)
        item = next(item for item in findings if item["analysis_type"] == "flash_repay_account_flow")
        self.assertEqual(item["status"], "flash_repay_path_requires_identity_and_balance_review")
        self.assertEqual(item["priority"], "HIGH_REVIEW")

    def test_untyped_selector_flows_to_config_value_sink(self):
        source = '''
        pub fn deposit(asset_id: u8, user_token_account: AccountInfo, amount: u64) -> Result<()> {
            let selected_reserve = reserves[asset_id as usize];
            let config_mint = selected_reserve.collateral_mint;
            let decimals = selected_reserve.collateral_decimals;
            let price = read_oracle_price(selected_reserve.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        findings = self.analyze_dataflow(source)
        finding = next(item for item in findings if item["function"] == "deposit")
        self.assertEqual(finding["dataflow_status"], "untyped_asset_selector_to_config_value_flow_review_required")
        self.assertTrue(finding["evidence"]["flows"]["asset_selector_seen"])
        self.assertTrue(finding["evidence"]["flows"]["selector_to_config_value_sink"])

    def test_anchor_bound_negative_fixture_does_not_report_unbound_identity(self):
        source = '''
        #[derive(Accounts)]
        pub struct MarginfiLikeDeposit<'info> {
            #[account(token::mint = liquidity_mint)]
            pub source_token_account: InterfaceAccount<'info, TokenAccount>,
            #[account(has_one = liquidity_mint)]
            pub bank: Account<'info, Bank>,
            pub liquidity_mint: InterfaceAccount<'info, Mint>,
        }
        pub fn deposit(ctx: Context<MarginfiLikeDeposit>, amount: u64) -> Result<()> {
            let bank = ctx.accounts.bank;
            let config_mint = bank.liquidity_mint;
            let decimals = bank.liquidity_mint_decimals;
            let price = read_oracle_price(ctx.accounts.oracle)?;
            let value = amount * price / 10u64.pow(decimals as u32);
            update_borrow_capacity(value);
            Ok(())
        }
        '''
        findings = self.analyze_dataflow(source)
        deposit = next(item for item in findings if item["function"] == "deposit")
        self.assertNotEqual(deposit["dataflow_status"], "potential_unbound_mint_to_config_value_flow_review_required")
        self.assertTrue(deposit["evidence"]["flows"]["mint_binding_guard_observed"])

    def test_protocol_inspired_fixture_suite_is_explicitly_synthetic(self):
        fixtures = Path(__file__).parents[1] / "sample" / "v05_regressions"
        self.assertTrue((fixtures / "loopscale_selector.rs").exists())
        self.assertTrue((fixtures / "kamino_extension_arithmetic.rs").exists())
        self.assertTrue((fixtures / "marginfi_anchor_bound.rs").exists())
        self.assertTrue((fixtures / "ydelta_anchor_bound.rs").exists())
        readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
        self.assertIn("synthetic protocol-inspired fixtures", readme)


    def test_four_protocol_inspired_regression_expectations(self):
        fixtures = Path(__file__).parents[1] / "sample" / "v05_regressions"
        loopscale = identity_dataflow.analyze_rust_file(fixtures / "loopscale_selector.rs")
        self.assertTrue(any(item["dataflow_status"] == "untyped_asset_selector_to_config_value_flow_review_required" for item in loopscale))

        kamino = protocol_analysis.analyze_rust_file(fixtures / "kamino_extension_arithmetic.rs")
        kamino_types = {item["analysis_type"] for item in kamino}
        self.assertIn("token_2022_extension_policy", kamino_types)
        self.assertIn("financial_arithmetic_review", kamino_types)
        self.assertIn("flash_repay_account_flow", kamino_types)

        for name in ("marginfi_anchor_bound.rs", "ydelta_anchor_bound.rs"):
            source = (fixtures / name).read_text(encoding="utf-8")
            contexts = protocol_analysis.parse_anchor_accounts(source)
            self.assertTrue(any(item["mint_guard"] for item in contexts.values()), name)
            dataflow = identity_dataflow.analyze_rust_file(fixtures / name)
            self.assertFalse(any(item["dataflow_status"] == "potential_unbound_mint_to_config_value_flow_review_required" for item in dataflow), name)


    def test_protocol_report_writer_emits_json_csv_and_review_pack(self):
        findings = [{
            "file": "sample.rs", "function": "deposit", "line": 10,
            "analysis_type": "flash_repay_account_flow", "status": "flash_repay_path_requires_identity_and_balance_review",
            "priority": "HIGH_REVIEW", "summary": "synthetic test",
        }]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            protocol_analysis.write_reports(findings, out)
            self.assertTrue((out / "protocol_analysis.json").exists())
            self.assertTrue((out / "protocol_analysis.csv").exists())
            self.assertTrue(list((out / "protocol_analysis_review").glob("*.md")))

    def test_legacy_scanner_attaches_structured_anchor_constraint_map(self):
        source = '''
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            #[account(token::mint = collateral_mint)]
            pub source_token_account: InterfaceAccount<'info, TokenAccount>,
            #[account(has_one = collateral_mint)]
            pub market: Account<'info, Market>,
            pub collateral_mint: Account<'info, Mint>,
        }
        pub fn deposit(ctx: Context<Deposit>, asset_id: u16, amount: u64) -> Result<()> {
            let selected_market = markets[asset_id as usize];
            transfer_checked();
            read_oracle_price();
            update_borrow_capacity(amount);
            Ok(())
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "anchor_legacy.rs"
            path.write_text(source, encoding="utf-8")
            findings = scanner.scan_rust(path)
        self.assertTrue(findings)
        self.assertTrue(any(item.get("anchor_context_constraint_map", {}).get("mint_guard") for item in findings))



if __name__ == "__main__":
    unittest.main()
