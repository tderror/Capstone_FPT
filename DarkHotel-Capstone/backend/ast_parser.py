"""
AST Parser Module - Advanced Code Analysis for Solidity
========================================================
Performs deep code analysis using AST (Abstract Syntax Tree):
1. Detect Pragma Version
2. Parse with tree-sitter-solidity (primary)
3. Fall back to Regex Parser if tree-sitter fails
4. Extract: Contracts, Functions, State Variables, Modifiers, Line Numbers

Parse priority: tree-sitter-solidity > regex fallback
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass

# tree-sitter-solidity (optional, graceful fallback)
try:
    import tree_sitter_solidity as _tssol
    from tree_sitter import Language as _TSLanguage, Parser as _TSParser
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False


@dataclass
class StateVariable:
    """Represents a state variable"""
    name: str
    var_type: str
    visibility: str
    line: int
    is_mapping: bool = False
    is_array: bool = False


@dataclass
class Modifier:
    """Represents a modifier"""
    name: str
    line: int
    parameters: List[str]


@dataclass
class Function:
    """Represents a function"""
    name: str
    visibility: str
    mutability: str  # view, pure, payable, nonpayable
    start_line: int
    end_line: int
    parameters: List[Dict]
    modifiers: List[str]
    has_external_call: bool = False
    has_state_change: bool = False
    code: str = ""


@dataclass
class Contract:
    """Represents a contract"""
    name: str
    contract_type: str  # contract, interface, library, abstract
    start_line: int
    end_line: int
    inheritance: List[str]
    state_variables: List[StateVariable]
    functions: List[Function]
    modifiers: List[Modifier]


@dataclass
class ASTResult:
    """Complete AST parsing result"""
    solidity_version: str
    compiler_version: str
    contracts: List[Contract]
    total_lines: int
    parse_method: str  # "tree-sitter" or "regex"
    errors: List[str]


class SolidityASTParser:
    """
    Advanced Solidity AST Parser

    Workflow:
    1. Detect pragma solidity version
    2. Parse with tree-sitter-solidity (primary)
    3. Fall back to regex parser if tree-sitter fails
    4. Extract all code elements
    """

    def __init__(self):
        # Initialize tree-sitter if available
        self.ts_available = False
        if _TS_AVAILABLE:
            try:
                self._ts_language = _TSLanguage(_tssol.language())
                self._ts_parser = _TSParser(self._ts_language)
                self.ts_available = True
            except Exception:
                self.ts_available = False

    def parse(self, code: str) -> ASTResult:
        """
        Main entry point - parse Solidity code

        Parse priority: tree-sitter-solidity > regex fallback
        Returns ASTResult with all extracted information
        """
        total_lines = len(code.split('\n'))
        solidity_version = self._detect_pragma_version(code)
        errors = []

        # Priority 1: tree-sitter-solidity (fast, no compilation needed)
        if self.ts_available:
            try:
                ts_result = self._parse_with_tree_sitter(code, solidity_version)
                ts_result.total_lines = total_lines
                ts_result.errors = errors
                return ts_result
            except Exception as e:
                errors.append(f"tree-sitter parsing failed: {str(e)}")

        # Priority 2: regex fallback
        regex_result = self._parse_with_regex(code)
        regex_result.solidity_version = solidity_version
        regex_result.total_lines = total_lines
        regex_result.errors = errors

        return regex_result

    def _detect_pragma_version(self, code: str) -> str:
        """Detect Solidity version from pragma statement"""
        patterns = [
            r'pragma\s+solidity\s+[\^~>=<]*(\d+\.\d+\.\d+)',
            r'pragma\s+solidity\s+[\^~>=<]*(\d+\.\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                return match.group(1)

        return "unknown"

    # ─── tree-sitter parsing ─────────────────────────────────────────

    def _parse_with_tree_sitter(self, code: str, version: str) -> ASTResult:
        """Parse using tree-sitter-solidity for fast, accurate AST"""
        tree = self._ts_parser.parse(bytes(code, "utf-8"))
        root = tree.root_node
        contracts = []

        for node in root.children:
            if node.type in (
                "contract_declaration",
                "interface_declaration",
                "library_declaration",
            ):
                contract = self._ts_extract_contract(node, code)
                contracts.append(contract)

        return ASTResult(
            solidity_version=version,
            compiler_version="tree-sitter",
            contracts=contracts,
            total_lines=0,
            parse_method="tree-sitter",
            errors=[],
        )

    def _ts_node_text(self, node, code_bytes: bytes) -> str:
        """Get text content of a tree-sitter node"""
        return code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _ts_find_children(self, node, type_name: str) -> list:
        """Find all direct children of a specific type"""
        return [c for c in node.children if c.type == type_name]

    def _ts_find_child(self, node, type_name: str):
        """Find first direct child of a specific type"""
        for c in node.children:
            if c.type == type_name:
                return c
        return None

    def _ts_find_descendants(self, node, type_name: str) -> list:
        """Find all descendants of a specific type (recursive)"""
        results = []
        for c in node.children:
            if c.type == type_name:
                results.append(c)
            results.extend(self._ts_find_descendants(c, type_name))
        return results

    def _ts_extract_contract(self, node, code: str) -> Contract:
        """Extract Contract from a tree-sitter contract_declaration node"""
        code_bytes = bytes(code, "utf-8")

        # Contract name
        name_node = self._ts_find_child(node, "identifier")
        contract_name = self._ts_node_text(name_node, code_bytes) if name_node else "Unknown"

        # Contract type
        type_map = {
            "contract_declaration": "contract",
            "interface_declaration": "interface",
            "library_declaration": "library",
        }
        contract_type = type_map.get(node.type, "contract")

        # Check abstract
        for child in node.children:
            if child.type == "abstract" or self._ts_node_text(child, code_bytes) == "abstract":
                contract_type = "abstract"
                break

        # Lines (tree-sitter uses 0-indexed rows)
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1

        # Inheritance
        inheritance = []
        for inh_node in self._ts_find_children(node, "inheritance_specifier"):
            for anc in self._ts_find_descendants(inh_node, "user_defined_type"):
                inheritance.append(self._ts_node_text(anc, code_bytes))

        # Find contract body
        body_node = self._ts_find_child(node, "contract_body")
        if not body_node:
            return Contract(
                name=contract_name, contract_type=contract_type,
                start_line=start_line, end_line=end_line,
                inheritance=inheritance, state_variables=[], functions=[], modifiers=[],
            )

        # State variables
        state_vars = []
        for sv_node in self._ts_find_children(body_node, "state_variable_declaration"):
            sv = self._ts_extract_state_variable(sv_node, code_bytes)
            if sv:
                state_vars.append(sv)

        state_var_names = [sv.name for sv in state_vars]

        # Functions
        functions = []
        for func_node in self._ts_find_children(body_node, "function_definition"):
            func = self._ts_extract_function(func_node, code, code_bytes, state_var_names)
            if func:
                functions.append(func)

        # Constructors
        for ctor_node in self._ts_find_children(body_node, "constructor_definition"):
            func = self._ts_extract_function(ctor_node, code, code_bytes, state_var_names, is_constructor=True)
            if func:
                functions.append(func)

        # Fallback / receive
        for fb_type in ("fallback_receive_definition",):
            for fb_node in self._ts_find_children(body_node, fb_type):
                func = self._ts_extract_function(fb_node, code, code_bytes, state_var_names, is_special=True)
                if func:
                    functions.append(func)

        # Modifiers
        modifiers = []
        for mod_node in self._ts_find_children(body_node, "modifier_definition"):
            mod = self._ts_extract_modifier_def(mod_node, code_bytes)
            if mod:
                modifiers.append(mod)

        return Contract(
            name=contract_name, contract_type=contract_type,
            start_line=start_line, end_line=end_line,
            inheritance=inheritance, state_variables=state_vars,
            functions=functions, modifiers=modifiers,
        )

    def _ts_extract_state_variable(self, node, code_bytes: bytes) -> Optional[StateVariable]:
        """Extract StateVariable from tree-sitter node"""
        text = self._ts_node_text(node, code_bytes)
        line = node.start_point[0] + 1

        # Name: last identifier before '=' or ';'
        identifiers = self._ts_find_descendants(node, "identifier")
        name = identifiers[-1].text.decode() if identifiers else ""
        if not name:
            return None

        # Type
        type_name_node = self._ts_find_child(node, "type_name")
        var_type = self._ts_node_text(type_name_node, code_bytes) if type_name_node else "unknown"

        # Visibility
        visibility = "internal"
        for child in node.children:
            if child.type in ("public", "private", "internal", "external"):
                visibility = child.type
            elif child.type == "visibility" or (hasattr(child, 'text') and child.text and child.text.decode() in ("public", "private", "internal")):
                visibility = child.text.decode() if hasattr(child, 'text') and child.text else visibility

        is_mapping = "mapping" in var_type.lower()
        is_array = "[]" in var_type

        return StateVariable(
            name=name, var_type=var_type, visibility=visibility,
            line=line, is_mapping=is_mapping, is_array=is_array,
        )

    def _ts_extract_function(self, node, code: str, code_bytes: bytes,
                             state_var_names: list, is_constructor: bool = False,
                             is_special: bool = False) -> Optional[Function]:
        """Extract Function from tree-sitter node"""
        # Name
        if is_constructor:
            name = "constructor"
        elif is_special:
            text = self._ts_node_text(node, code_bytes)
            if "receive" in text[:30]:
                name = "receive"
            elif "fallback" in text[:30]:
                name = "fallback"
            else:
                name = "fallback"
        else:
            name_node = self._ts_find_child(node, "identifier")
            name = self._ts_node_text(name_node, code_bytes) if name_node else ""
            if not name:
                return None

        # Lines & code
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        func_code = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

        # Visibility & mutability
        visibility = "public" if is_constructor else "internal"
        mutability = "nonpayable"
        for child in node.children:
            ct = child.type
            if ct in ("public", "private", "internal", "external"):
                visibility = ct
            elif ct in ("pure", "view", "payable"):
                mutability = ct
            elif ct == "visibility":
                txt = child.text.decode() if child.text else ""
                if txt in ("public", "private", "internal", "external"):
                    visibility = txt
            elif ct == "state_mutability":
                txt = child.text.decode() if child.text else ""
                if txt in ("pure", "view", "payable"):
                    mutability = txt

        # Parameters
        params = []
        param_list = self._ts_find_child(node, "parameter")
        if not param_list:
            param_list = self._ts_find_child(node, "parameter_list")
        if param_list:
            for p in param_list.children:
                if p.type == "parameter":
                    p_type_node = self._ts_find_child(p, "type_name")
                    p_name_node = self._ts_find_child(p, "identifier")
                    params.append({
                        "type": self._ts_node_text(p_type_node, code_bytes) if p_type_node else "unknown",
                        "name": self._ts_node_text(p_name_node, code_bytes) if p_name_node else "",
                    })

        # Modifiers used
        mods = []
        for child in node.children:
            if child.type == "modifier_invocation":
                mod_name_node = self._ts_find_child(child, "identifier")
                if mod_name_node:
                    mods.append(self._ts_node_text(mod_name_node, code_bytes))
        # Also check known modifier keywords in function text
        known_mods = ['onlyOwner', 'nonReentrant', 'whenNotPaused', 'whenPaused',
                      'onlyAdmin', 'onlyRole', 'initializer', 'reinitializer']
        for mod in known_mods:
            if mod in func_code and mod not in mods:
                mods.append(mod)

        # External call & state change detection (reuse existing regex helpers)
        has_ext_call = self._has_external_call(func_code)
        has_state_change = mutability not in ("view", "pure") and self._has_state_change(func_code, state_var_names)

        return Function(
            name=name, visibility=visibility, mutability=mutability,
            start_line=start_line, end_line=end_line,
            parameters=params, modifiers=mods,
            has_external_call=has_ext_call, has_state_change=has_state_change,
            code=func_code,
        )

    def _ts_extract_modifier_def(self, node, code_bytes: bytes) -> Optional[Modifier]:
        """Extract Modifier definition from tree-sitter node"""
        name_node = self._ts_find_child(node, "identifier")
        name = self._ts_node_text(name_node, code_bytes) if name_node else ""
        if not name:
            return None
        line = node.start_point[0] + 1
        params = []
        param_list = self._ts_find_child(node, "parameter_list")
        if param_list:
            for p in self._ts_find_descendants(param_list, "identifier"):
                params.append(self._ts_node_text(p, code_bytes))
        return Modifier(name=name, line=line, parameters=params)

    # ─── regex fallback parsing ──────────────────────────────────────

    @staticmethod
    def _strip_strings_and_comments(line: str) -> str:
        """Remove string literals and comments from a line for accurate brace counting"""
        # Remove single-line comments
        result = re.sub(r'//.*$', '', line)
        # Remove string literals (double and single quoted)
        result = re.sub(r'"(?:[^"\\]|\\.)*"', '""', result)
        result = re.sub(r"'(?:[^'\\]|\\.)*'", "''", result)
        return result

    def _find_block_end(self, lines: List[str], start_idx: int) -> int:
        """Find the end index of a brace-delimited block, ignoring braces in strings/comments"""
        brace_count = 0
        found_open = False
        for j in range(start_idx, len(lines)):
            cleaned = self._strip_strings_and_comments(lines[j])
            brace_count += cleaned.count('{')
            brace_count -= cleaned.count('}')
            if not found_open and '{' in cleaned:
                found_open = True
            if found_open and brace_count == 0:
                return j
        return len(lines) - 1

    def _parse_with_regex(self, code: str) -> ASTResult:
        """
        Fallback regex-based parser
        Used when tree-sitter is not available
        """
        contracts = []
        lines = code.split('\n')

        # Find all contracts
        contract_pattern = r'(contract|interface|library|abstract\s+contract)\s+(\w+)(?:\s+is\s+([^{]+))?'

        i = 0
        while i < len(lines):
            line = lines[i]
            match = re.search(contract_pattern, line)

            if match:
                contract_type = match.group(1).replace("abstract ", "")
                contract_name = match.group(2)
                inheritance_str = match.group(3) or ""
                inheritance = [x.strip() for x in inheritance_str.split(',') if x.strip()]

                start_line = i + 1
                end_idx = self._find_block_end(lines, i)
                end_line = end_idx + 1

                contract_code = '\n'.join(lines[i:end_idx + 1])

                # Extract elements from contract
                state_vars = self._extract_state_vars_regex(contract_code, start_line)
                state_var_names = [sv.name for sv in state_vars]
                functions = self._extract_functions_regex(contract_code, start_line, state_var_names)
                modifiers = self._extract_modifiers_regex(contract_code, start_line)

                contracts.append(Contract(
                    name=contract_name,
                    contract_type=contract_type,
                    start_line=start_line,
                    end_line=end_line,
                    inheritance=inheritance,
                    state_variables=state_vars,
                    functions=functions,
                    modifiers=modifiers
                ))

                i = end_line
            else:
                i += 1

        return ASTResult(
            solidity_version="unknown",
            compiler_version="regex",
            contracts=contracts,
            total_lines=len(lines),
            parse_method="regex",
            errors=[]
        )

    def _extract_state_vars_regex(self, code: str, base_line: int) -> List[StateVariable]:
        """Extract state variables using regex"""
        state_vars = []
        lines = code.split('\n')

        # Track brace depth to only extract top-level declarations (depth == 1)
        brace_depth = 0

        # Broad pattern: primitive types, custom types (IERC20, MyStruct), address payable
        var_pattern = (
            r'^\s*'
            r'(mapping\s*\([^)]+\)|'                    # mapping(...)
            r'uint\d*|int\d*|address(?:\s+payable)?|'    # primitive types
            r'bool|string|bytes\d*|'                     # more primitives
            r'[A-Z]\w*)'                                 # custom types (IERC20, MyStruct, etc.)
            r'\s*(?:\[[^\]]*\])?'                        # optional array brackets
            r'\s*(public|private|internal|external)?'     # visibility
            r'\s+(\w+)'                                  # variable name
            r'\s*[;=]'                                   # ends with ; or =
        )
        mapping_pattern = r'mapping\s*\([^)]+\)\s*(public|private|internal)?\s*(\w+)'

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                continue

            # Skip event/error/using/import/pragma declarations
            if re.match(r'^\s*(event|error|using|import|pragma|emit)\b', line):
                continue

            # Skip function/modifier/constructor declarations
            if re.match(r'^\s*(function|modifier|constructor|receive|fallback)\b', line):
                brace_depth += line.count('{') - line.count('}')
                continue

            # Track brace depth
            brace_depth += line.count('{') - line.count('}')

            # Only extract state vars at contract body level (depth == 1)
            if brace_depth != 1:
                continue

            # Check mapping
            match = re.search(mapping_pattern, line)
            if match:
                visibility = match.group(1) or "internal"
                name = match.group(2)
                state_vars.append(StateVariable(
                    name=name,
                    var_type="mapping",
                    visibility=visibility,
                    line=base_line + i,
                    is_mapping=True
                ))
                continue

            # Check regular variables
            match = re.search(var_pattern, line)
            if match:
                var_type = match.group(1)
                visibility = match.group(2) or "internal"
                name = match.group(3)
                state_vars.append(StateVariable(
                    name=name,
                    var_type=var_type,
                    visibility=visibility,
                    line=base_line + i,
                    is_array="[]" in line
                ))

        return state_vars

    def _extract_functions_regex(self, code: str, base_line: int, state_var_names: list = None) -> List[Function]:
        """Extract functions using regex (includes constructor/receive/fallback)"""
        functions = []
        lines = code.split('\n')

        # Patterns for different function types
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(public|private|internal|external)?\s*(view|pure|payable)?'
        ctor_pattern = r'constructor\s*\(([^)]*)\)\s*(public|private|internal)?'
        recv_pattern = r'receive\s*\(\s*\)\s*(external)?\s*(payable)?'
        fb_pattern = r'fallback\s*\(\s*\)\s*(external)?\s*(payable)?'

        i = 0
        while i < len(lines):
            line = lines[i]

            name = None
            params_str = ""
            visibility = "internal"
            mutability = "nonpayable"

            # Check named function
            match = re.search(func_pattern, line)
            if match:
                name = match.group(1)
                params_str = match.group(2)
                visibility = match.group(3) or "internal"
                mutability = match.group(4) or "nonpayable"
            else:
                # Check constructor
                match = re.search(ctor_pattern, line)
                if match:
                    name = "constructor"
                    params_str = match.group(1)
                    visibility = match.group(2) or "public"
                else:
                    # Check receive
                    match = re.search(recv_pattern, line)
                    if match:
                        name = "receive"
                        visibility = "external"
                        mutability = "payable"
                    else:
                        # Check fallback
                        match = re.search(fb_pattern, line)
                        if match:
                            name = "fallback"
                            visibility = "external"
                            mutability = match.group(2) or "nonpayable"

            if name:
                start_line = base_line + i

                # Find function end using safe brace counting
                end_idx = self._find_block_end(lines, i)
                end_line = base_line + end_idx

                func_code = '\n'.join(lines[i:end_idx + 1])

                # Parse parameters
                params = []
                if params_str.strip():
                    for p in params_str.split(','):
                        parts = p.strip().split()
                        if len(parts) >= 2:
                            params.append({"type": parts[0], "name": parts[-1]})

                # Extract modifiers used
                mods = self._extract_used_modifiers(func_code)

                # view/pure functions cannot modify state by Solidity compiler guarantee
                has_state_change = mutability not in ("view", "pure") and self._has_state_change(func_code, state_var_names)

                functions.append(Function(
                    name=name,
                    visibility=visibility,
                    mutability=mutability,
                    start_line=start_line,
                    end_line=end_line,
                    parameters=params,
                    modifiers=mods,
                    has_external_call=self._has_external_call(func_code),
                    has_state_change=has_state_change,
                    code=func_code
                ))

                i = end_idx + 1
            else:
                i += 1

        return functions

    def _extract_modifiers_regex(self, code: str, base_line: int) -> List[Modifier]:
        """Extract modifier definitions using regex"""
        modifiers = []
        lines = code.split('\n')

        mod_pattern = r'modifier\s+(\w+)\s*\(([^)]*)\)'

        for i, line in enumerate(lines):
            match = re.search(mod_pattern, line)
            if match:
                name = match.group(1)
                params_str = match.group(2)
                params = [p.strip().split()[-1] for p in params_str.split(',') if p.strip()]

                modifiers.append(Modifier(
                    name=name,
                    line=base_line + i,
                    parameters=params
                ))

        return modifiers

    def _extract_used_modifiers(self, func_code: str) -> List[str]:
        """Extract modifiers used in function declaration"""
        modifiers = []

        # Common modifiers
        known_mods = ['onlyOwner', 'nonReentrant', 'whenNotPaused', 'whenPaused',
                      'onlyAdmin', 'onlyRole', 'initializer', 'reinitializer']

        for mod in known_mods:
            if mod in func_code:
                modifiers.append(mod)

        return modifiers

    def _has_external_call(self, code: str) -> bool:
        """Check if function has external calls"""
        patterns = [
            r'\.call\{',
            r'\.call\.value',
            r'\.delegatecall',
            r'\.staticcall',
            r'\.send\(',
            r'\.transfer\s*\([^,)]+\)',  # ETH transfer (1 arg) only; ERC20 .transfer(to, amount) has comma → excluded
        ]

        for pattern in patterns:
            if re.search(pattern, code):
                return True
        return False

    def _has_state_change(self, code: str, state_var_names: list = None) -> bool:
        """Check if function modifies state variables.

        Uses dynamic regex with known state variable names to only match
        assignments to actual state variables (not local vars).
        """
        if state_var_names is None or not state_var_names:
            return False  # No state vars known → cannot detect state change

        vars_pattern = '|'.join(map(re.escape, state_var_names))
        patterns = [
            rf'\b(?:{vars_pattern})\b(?:\[[^\]]*\])?\s*=[^=]',       # x = ..., balances[a] = ...
            rf'\b(?:{vars_pattern})\b(?:\[[^\]]*\])?\s*[\+\-\*\/]=', # x += ..., balances[a] -= ...
            rf'\b(?:{vars_pattern})\b(?:\[[^\]]*\])?\s*(?:\+\+|--)', # x++, x--
            rf'delete\s+(?:{vars_pattern})\b',                       # delete x
            rf'\b(?:{vars_pattern})\b(?:\[[^\]]*\])?\.push\s*\(',    # x.push(...)
            rf'\b(?:{vars_pattern})\b(?:\[[^\]]*\])?\.pop\s*\(',     # x.pop()
        ]
        for pattern in patterns:
            if re.search(pattern, code):
                return True
        return False

    def get_function_chunks(self, result: ASTResult) -> List[Dict]:
        """
        Extract function chunks for RAG search.

        Returns list of function dicts with code for similarity search.
        Each chunk contains the function code and metadata.

        Args:
            result: ASTResult from parse()

        Returns:
            List of dicts: [
                {
                    'name': 'withdraw',
                    'contract': 'VulnerableBank',
                    'code': 'function withdraw() public { ... }',
                    'start_line': 15,
                    'end_line': 20,
                    'visibility': 'public',
                    'has_external_call': True,
                    'has_state_change': True,
                    'modifiers': ['onlyOwner'],
                    'risk_indicators': ['external_call_before_state_update']
                }
            ]
        """
        chunks = []

        for contract in result.contracts:
            for func in contract.functions:
                # Determine risk indicators
                risk_indicators = []

                if func.has_external_call:
                    risk_indicators.append("has_external_call")
                if func.has_state_change:
                    risk_indicators.append("has_state_change")
                if func.has_external_call and func.has_state_change:
                    # Potential reentrancy - external call + state change
                    risk_indicators.append("potential_reentrancy")
                if func.visibility in ["public", "external"] and "onlyOwner" not in func.modifiers:
                    if func.has_state_change:
                        risk_indicators.append("unprotected_state_change")
                if "nonReentrant" not in func.modifiers and func.has_external_call:
                    risk_indicators.append("no_reentrancy_guard")

                chunk = {
                    "name": func.name,
                    "contract": contract.name,
                    "code": func.code,
                    "start_line": func.start_line,
                    "end_line": func.end_line,
                    "visibility": func.visibility,
                    "mutability": func.mutability,
                    "has_external_call": func.has_external_call,
                    "has_state_change": func.has_state_change,
                    "modifiers": func.modifiers,
                    "parameters": func.parameters,
                    "risk_indicators": risk_indicators,
                    "priority": len(risk_indicators)  # Higher = more risky
                }

                chunks.append(chunk)

        # Sort by priority (most risky first)
        chunks.sort(key=lambda x: x["priority"], reverse=True)

        return chunks

    def get_risky_functions(self, result: ASTResult) -> List[Dict]:
        """
        Get only functions with potential vulnerabilities.

        Filters to functions that have:
        - External calls
        - State changes
        - Missing protection modifiers

        Args:
            result: ASTResult from parse()

        Returns:
            List of risky function chunks
        """
        all_chunks = self.get_function_chunks(result)
        return [c for c in all_chunks if c["priority"] > 0]

    def get_summary(self, result: ASTResult) -> Dict:
        """Get summary of parsed code"""
        total_functions = sum(len(c.functions) for c in result.contracts)
        total_state_vars = sum(len(c.state_variables) for c in result.contracts)
        total_modifiers = sum(len(c.modifiers) for c in result.contracts)

        external_call_funcs = []
        state_change_funcs = []

        for c in result.contracts:
            for f in c.functions:
                if f.has_external_call:
                    external_call_funcs.append(f"{c.name}.{f.name}")
                if f.has_state_change:
                    state_change_funcs.append(f"{c.name}.{f.name}")

        return {
            "solidity_version": result.solidity_version,
            "parse_method": result.parse_method,
            "total_lines": result.total_lines,
            "total_contracts": len(result.contracts),
            "total_functions": total_functions,
            "total_state_variables": total_state_vars,
            "total_modifiers": total_modifiers,
            "functions_with_external_calls": external_call_funcs,
            "functions_with_state_changes": state_change_funcs,
            "contracts": [c.name for c in result.contracts]
        }


# Test
if __name__ == "__main__":
    sample_code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract VulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier onlyPositiveBalance() {
        require(balances[msg.sender] > 0, "No balance");
        _;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw() public onlyPositiveBalance {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
}
"""

    parser = SolidityASTParser()
    result = parser.parse(sample_code)
    summary = parser.get_summary(result)

    print("=== AST Parser Result ===")
    print(f"Solidity Version: {summary['solidity_version']}")
    print(f"Parse Method: {summary['parse_method']}")
    print(f"Total Lines: {summary['total_lines']}")
    print(f"Contracts: {summary['contracts']}")
    print(f"Total Functions: {summary['total_functions']}")
    print(f"Total State Variables: {summary['total_state_variables']}")
    print(f"Functions with External Calls: {summary['functions_with_external_calls']}")
    print(f"Functions with State Changes: {summary['functions_with_state_changes']}")
