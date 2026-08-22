# SPDX-License-Identifier: MIT
"""Diagnostics emitted while loading a non-conforming database.

A message which does not name the element it is about cannot be acted upon
without searching the file by hand, which is what these cases used to require.
"""
import unittest
from xml.etree import ElementTree

from odxtools.matchingparameter import MatchingParameter
from odxtools.odxdoccontext import OdxDocContext
from odxtools.odxlink import DocType, OdxDocFragment
from odxtools.subcomponentparamconnector import SubComponentParamConnector

doc_frags = (OdxDocFragment("test", DocType.CONTAINER),)
context = OdxDocContext((2, 2, 0), doc_frags)


class TestLoadErrorContext(unittest.TestCase):

    def test_matching_parameter_without_output_names_the_diag_comm(self) -> None:
        et = ElementTree.fromstring("<MATCHING-PARAMETER>"
                                    "<EXPECTED-VALUE>42</EXPECTED-VALUE>"
                                    '<DIAG-COMM-SNREF SHORT-NAME="ReadIdent"/>'
                                    "</MATCHING-PARAMETER>")

        with self.assertRaises(Exception) as ctx:
            MatchingParameter.from_et(et, context)

        message = str(ctx.exception)
        self.assertIn("ReadIdent", message)
        self.assertIn("OUT-PARAM-IF-SNREF", message)

    def test_unsupported_param_ref_names_the_connector_and_the_tag(self) -> None:
        et = ElementTree.fromstring("<SUB-COMPONENT-PARAM-CONNECTOR ID=\"conn.1\">"
                                    "<SHORT-NAME>MyConnector</SHORT-NAME>"
                                    '<DIAG-COMM-SNREF SHORT-NAME="SomeService"/>'
                                    "<OUT-PARAM-IF-REFS>"
                                    '<OUT-PARAM-IF-REF ID-REF="x"/>'
                                    "</OUT-PARAM-IF-REFS>"
                                    "</SUB-COMPONENT-PARAM-CONNECTOR>")

        with self.assertRaises(Exception) as ctx:
            SubComponentParamConnector.from_et(et, context)

        message = str(ctx.exception)
        self.assertIn("MyConnector", message)
        self.assertIn("OUT-PARAM-IF-REF", message)


if __name__ == "__main__":
    unittest.main()
