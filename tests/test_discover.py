import unittest
from discover import valid_pubkey, extract_program_ids, score_candidate, merge_candidates, candidate_template, classify_repo_role

class DiscoverTests(unittest.TestCase):
    def test_valid_solana_pubkeys(self):
        self.assertTrue(valid_pubkey('11111111111111111111111111111111'))
        self.assertFalse(valid_pubkey('not-a-solana-address'))
        self.assertFalse(valid_pubkey('1111111111111111111111111111111'))

    def test_extract_ids_deduplicates_and_validates(self):
        text = 'Program: 11111111111111111111111111111111 and invalid 0x1234'
        self.assertEqual(extract_program_ids(text), ['11111111111111111111111111111111'])

    def test_score_prefers_lending_and_rpc_program(self):
        score, reasons = score_candidate('Example Lending', 'Lending', 'collateral borrow', 'https://github.com/a/b',
                                         '11111111111111111111111111111111', rpc_valid=True)
        self.assertGreaterEqual(score, 70)
        self.assertIn('RPC confirms executable program account', reasons)

    def test_merge_by_program_id_preserves_sources(self):
        a = candidate_template('A', 'defillama', 'directory evidence', program_id='11111111111111111111111111111111')
        b = candidate_template('A', 'github', 'repo evidence', program_id='11111111111111111111111111111111')
        result = merge_candidates([a,b])
        self.assertEqual(len(result), 1)
        self.assertEqual(set(result[0]['discovery_source']), {'defillama','github'})
        self.assertEqual(len(result[0]['evidence']), 2)

    def test_no_program_candidates_do_not_all_collapse(self):
        a = candidate_template('A', 'defillama', 'one')
        b = candidate_template('B', 'defillama', 'two')
        self.assertEqual(len(merge_candidates([a,b])), 2)

    def test_repository_role_marks_issuer_drill_as_research_poc(self):
        role = classify_repo_role('psyto/issuer-drill', '', 'This is a single-finding reproduction harness and security research project.')
        self.assertEqual(role, 'research_poc')

    def test_repository_role_never_auto_claims_official_source(self):
        role = classify_repo_role('some-org/lending', 'Solana lending protocol', 'Program source code')
        self.assertEqual(role, 'unverified_repository_candidate')

if __name__ == '__main__': unittest.main()
