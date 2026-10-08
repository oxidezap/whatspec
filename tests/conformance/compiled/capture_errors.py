#!/usr/bin/env python3
"""Capture the reviewed error-parser evidence with the shared verified AST flow.

Usage: python3 tests/conformance/compiled/capture_errors.py LOCK BUNDLES OUTPUT
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import capture

MODULES = [
    'WASmaxInGroupsIQErrorResponseMixin',
    'WASmaxInGroupsSetSubjectClientErrors',
    'WASmaxInGroupsAcceptGroupAddClientErrors',
    'WASmaxInGroupsServerErrors',
    'WASmaxInGroupsBaseServerErrorMixin',
    'WASmaxInGroupsSetSubjectResponseClientError',
    'WASmaxInGroupsAcceptGroupAddResponseClientError',
    'WASmaxInGroupsSetSubjectResponseServerError',
    'WASmaxInGroupsAcceptGroupAddResponseServerError',
    'WASmaxParseUtils',
    'WASmaxParseReference',
    'WASmaxInGroupsIQErrorNotAcceptableMixin',
    'WASmaxInGroupsIQErrorResourceConstraintMixin',
    'WASmaxInGroupsIQErrorFallbackClientMixin',
    'WASmaxInGroupsIQErrorFallbackServerMixin',
    'WASmaxInGroupsIQErrorAlreadyExistsMixin',
    'WASmaxInGroupsIQErrorBadRequestMixin',
    'WASmaxInGroupsIQErrorInternalServerErrorMixin',
    'WASmaxInGroupsIQErrorServiceUnavailableMixin',
    'WASmaxInGroupsIQErrorPartialServerErrorMixin',
]

if __name__ == '__main__':
    capture.MODULES = MODULES
    capture.capture(*(Path(arg) for arg in sys.argv[1:]))
