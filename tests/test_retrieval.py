from unittest.mock import patch, MagicMock

from backend.schemas import Issue, VulnType, Severity, IssueCategory


class TestRetrieval:
    @patch("retrieval_layer.retriever.query")
    def test_retrieve_returns_cwe(self, mock_query):
        mock_query.return_value = [
            {
                "document": "SQL Injection occurs when user input is concatenated into queries.",
                "cwe_id": "CWE-89",
                "source_url": "https://cwe.mitre.org/data/definitions/89.html",
                "vuln_type": "sql_injection",
                "score": 0.92,
            }
        ]
        from retrieval_layer.retriever import retrieve
        result = retrieve("sql_injection", 'SELECT * FROM users WHERE name = " + name')
        assert result is not None
        assert result.cwe_reference == "CWE-89"
        assert "SQL Injection" in result.retrieved_text
        mock_query.assert_called_once()

    @patch("retrieval_layer.retriever.query")
    def test_retrieve_returns_none_on_empty(self, mock_query):
        mock_query.return_value = []
        from retrieval_layer.retriever import retrieve
        result = retrieve("sql_injection", "safe code")
        assert result is None


class TestSynthesizer:
    def test_synthesize_returns_none_without_keys(self):
        import llm_synthesis.synthesizer as syn
        with patch.object(syn, "GEMINI_API_KEY", ""), \
             patch.object(syn, "GROQ_API_KEY", ""):
            issue = Issue(
                line=1,
                vuln_type=VulnType.SQL_INJECTION,
                snippet='q = "SELECT * FROM t WHERE x = " + x',
                confidence="high",
                severity=Severity.HIGH,
            )
            from retrieval_layer.retriever import RetrievalResult
            retrieval = RetrievalResult(
                retrieved_text="SQL Injection mitigation text",
                cwe_reference="CWE-89",
                source_url="https://cwe.mitre.org/data/definitions/89.html",
            )
            result = syn.synthesize(issue, retrieval)
        assert result is None

    @patch("llm_synthesis.synthesizer.GEMINI_API_KEY", "test-key")
    @patch("llm_synthesis.synthesizer._call_gemini")
    def test_synthesize_parses_json(self, mock_gemini):
        mock_gemini.return_value = (
            '{"explanation": "This is vulnerable.", '
            '"secure_rewrite": "safe_code()", '
            '"cwe_reference": "CWE-89"}'
        )
        from llm_synthesis.synthesizer import synthesize
        issue = Issue(
            line=1,
            vuln_type=VulnType.SQL_INJECTION,
            snippet='q = "SELECT * FROM t WHERE x = " + x',
            confidence="high",
            severity=Severity.HIGH,
        )
        from retrieval_layer.retriever import RetrievalResult
        retrieval = RetrievalResult(
            retrieved_text="SQL Injection text",
            cwe_reference="CWE-89",
            source_url="https://cwe.mitre.org/data/definitions/89.html",
        )
        result = synthesize(issue, retrieval)
        assert result is not None
        assert "vulnerable" in result.explanation
        assert "safe_code()" in result.secure_rewrite
        assert result.cwe_reference == "CWE-89"


class TestPrompts:
    def test_build_prompt_includes_vuln_type(self):
        from llm_synthesis.prompts import build_prompt
        prompt = build_prompt("sql_injection", 'q = "SELECT * FROM t"', "Some CWE text")
        assert "Sql Injection" in prompt
        assert "SELECT" in prompt
        assert "Some CWE text" in prompt

    def test_build_prompt_asks_for_json(self):
        from llm_synthesis.prompts import build_prompt
        prompt = build_prompt("xss", '{{ content|safe }}', "XSS text")
        assert '"explanation"' in prompt
        assert '"secure_rewrite"' in prompt
        assert '"cwe_reference"' in prompt
