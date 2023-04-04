"""
Module detecting missing zero address validation

"""
from collections import defaultdict
from typing import DefaultDict, List, Tuple, Union

from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.core.cfg.node import Node
from slither.core.declarations.contract import Contract
from slither.core.declarations.function import ModifierStatements
from slither.core.declarations.function_contract import FunctionContract
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.local_variable import LocalVariable
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Call
from slither.slithir.operations import Send, Transfer, LowLevelCall
from slither.utils.output import Output


class MissingZeroAddressValidation(AbstractDetector):
    """
    Missing zero address validation
    """

    ARGUMENT = "missing-zero-check"
    HELP = "Missing Zero Address Validation"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation"
    WIKI_TITLE = "Missing zero address validation"
    WIKI_DESCRIPTION = "Detect missing zero address validation."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract C {

  modifier onlyAdmin {
    if (msg.sender != owner) throw;
    _;
  }

  function updateOwner(address newOwner) onlyAdmin external {
    owner = newOwner;
  }
}
```
Bob calls `updateOwner` without specifying the `newOwner`, so Bob loses ownership of the contract.
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Check that the address is not zero."

    def _zero_address_validation_in_modifier(
        self, var: LocalVariable, modifier_exprs: List[ModifierStatements]
    ) -> bool:
        for mod in modifier_exprs:
            for node in mod.nodes:
                # Skip validation if the modifier's parameters contains more than one variable
                # For example
                # function f(a) my_modif(some_internal_function(a, b)) {
                if len(node.irs) != 1:
                    continue
                args = [arg for ir in node.irs if isinstance(ir, Call) for arg in ir.arguments]
                # Check in modifier call arguments and then identify validation of corresponding parameter within modifier context
                if var in args and self._zero_address_validation(
                    mod.modifier.parameters[args.index(var)], mod.modifier.nodes[-1], []
                ):
                    return True
        return False

    def _zero_address_validation(
        self, var: LocalVariable, node: Node, explored: List[Node]
    ) -> bool:
        """
        Detects (recursively) if var is (zero address) checked in the function node
        """

        if node in explored:
            return False
        explored.append(node)

        # Heuristic: Assume zero address checked if variable is used within conditional or require/assert
        # TBD: Actually check for zero address in predicate
        if (node.contains_if() or node.contains_require_or_assert()) and (
            var in node.variables_read
        ):
            return True

        # Check recursively in all the parent nodes
        for father in node.fathers:
            if self._zero_address_validation(var, father, explored):
                return True
        return False

        def _detect_missing_zero_address_validation(
        self, contract: Contract
    ) -> List[Tuple[FunctionContract, DefaultDict[LocalVariable, List[Node]]]]:
    """
    Detects missing zero-address validations in the constructors and functions of the given contract and its parent contracts.
    
    :param contract: The contract to analyze.
    :return: A list of tuples containing functions/constructors with missing zero-address validations and the corresponding local variables and nodes.
    """
    # Stores the functions/constructors with missing zero-address validations and the corresponding local variables and nodes.
    results = []

    def check_parent_constructors(var: LocalVariable, child_constructor: FunctionContract) -> bool:
        """
        Checks if a given variable has a zero-address validation in any of the parent constructors.
        
        :param var: The local variable to check.
        :param child_constructor: The constructor of the child contract.
        :return: True if a zero-address validation is found in any parent constructor, False otherwise.
        """
        # Iterate over the parent contracts in the inheritance chain.
        for parent in child_constructor.contract.inheritance:
            parent_constructor = parent.constructor
            if parent_constructor:
                # Check if the zero-address validation is performed for the given variable in the parent constructor.
                if self._zero_address_validation(var, parent_constructor.entry_point, []):
                    return True
        return False

    def analyze_function(function: FunctionContract):
        """
        Analyzes a function or constructor for missing zero-address validations.
        
        :param function: The function or constructor to analyze.
        """
        # Stores local variables with missing zero-address validations and the corresponding nodes.
        var_nodes = defaultdict(list)

        # Iterate over the nodes in the function/constructor.
        for node in function.nodes:
            # Filter state variables of type "address" that are written in the node.
            sv_addrs_written = [
                sv
                for sv in node.state_variables_written
                if sv.type == ElementaryType("address")
            ]

            # Check if the node contains Send, Transfer, or LowLevelCall operations.
            addr_calls = False
            for ir in node.irs:
                if isinstance(ir, (Send, Transfer, LowLevelCall)):
                    addr_calls = True

            # Skip the node if there are no address state variables written and no address calls.
            if not sv_addrs_written and not addr_calls:
                continue

            # Check local variables read in the node.
            for var in node.local_variables_read:
                if var.type == ElementaryType("address") and is_tainted(var, function, ignore_generic_taint=True):
                    # If zero-address validation is performed in the parent constructor or the current function/constructor, skip the variable.
                    if (
                        check_parent_constructors(var, function)
                        or self._zero_address_validation_in_modifier(var, function.modifiers_statements)
                        or self._zero_address_validation(var, node, [])
                    ):
                        continue

                    # Store the variable and the node if zero-address validation is missing.
                    var_nodes[var].append(node)
        
        # Append the results if there are any missing zero-address validations.
        if var_nodes:
            results.append((function, var_nodes))

    # Analyze the constructor of the current contract.
    constructor = contract.constructor
    if constructor:
        analyze_function(constructor)

    # Analyze the constructors of the parent contracts.
    for parent in contract.inheritance:
        parent_constructor = parent.constructor
        if parent_constructor:
            analyze_function(parent_constructor)

    # Analyze the functions entry points of the current contract.
   
    for function in contract.functions_entry_points:
        analyze_function(function)

    return results



    def _detect(self) -> List[Output]:
        """Detect if addresses are zero address validated before use.
        Returns:
            list: {'(function, node)'}
        """

        # Check derived contracts for missing zero address validation
        results = []
        for contract in self.compilation_unit.contracts_derived:
            missing_zero_address_validation = self._detect_missing_zero_address_validation(contract)
            for (_, var_nodes) in missing_zero_address_validation:
                for var, nodes in var_nodes.items():
                    info = [var, " lacks a zero-check on ", ":\n"]
                    for node in nodes:
                        info += ["\t\t- ", node, "\n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results