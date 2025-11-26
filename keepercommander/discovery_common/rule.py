from __future__ import annotations
from .types import (RuleTypeEnum, RuleItem, ActionRuleSet, ActionRuleItem, ScheduleRuleSet, ComplexityRuleSet,
                    Statement, RuleActionEnum)
from .utils import value_to_boolean, get_connection, make_agent
from ..keeper_dag import DAG, EdgeType
from ..keeper_dag.exceptions import DAGException
from ..keeper_dag.types import PamGraphId, PamEndpoints
from time import time
import base64
import os
from typing import Any, List, Optional, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from .types import DiscoveryObject


class Rules:

    DATA_PATH = "rules"
    RULE_ITEM_TYPE_MAP = {
        "ActionRuleItem": RuleTypeEnum.ACTION,
        "ScheduleRuleItem": RuleTypeEnum.SCHEDULE,
        "ComplexityRuleItem": RuleTypeEnum.COMPLEXITY
    }
    RULE_TYPE_TO_SET_MAP = {
        RuleTypeEnum.ACTION: ActionRuleSet,
        RuleTypeEnum.SCHEDULE: ScheduleRuleSet,
        RuleTypeEnum.COMPLEXITY: ComplexityRuleSet
    }

    RULE_FIELDS = {
        # Attributes the records
        "recordType": {"type": str},
        "parentRecordType": {"type": str},
        "recordTitle": {"type": str},
        "recordNotes": {"type": str},
        "recordDesc": {"type": str},
        "parentUid": {"type": str},

        # Record fields
        "login": {"type": str},
        "password": {"type": str},
        "privatePEMKey": {"type": str},
        "distinguishedName": {"type": str},
        "connectDatabase": {"type": str},
        "managed": {"type": bool, "default": False},
        "hostName": {"type": str},
        "port": {"type": float, "default": 0},
        "operatingSystem": {"type": str},
        "instanceName": {"type": str},
        "instanceId": {"type": str},
        "providerGroup": {"type": str},
        "providerRegion": {"type": str},
        "databaseId": {"type": str},
        "databaseType": {"type": str},
        "useSSL": {"type": bool, "default": False},
        "domainName": {"type": str},
        "directoryId": {"type": str},
        "directoryType": {"type": str},
    }

    BREAK_OUT = {
        "pamHostname": {
            "hostName": "hostName",
            "port": "port"
        }
    }

    RECORD_FIELD = {
        "pamMachine": ["pamHostname"],
        "pamDatabase": ["pamHostname", "databaseType"],
        "pamDirectory": ["pamHostname", "directoryType"],
        "pamUser": ["parentUid", "login", "distinguishedName"],
    }

    OBJ_ATTR = {
        "parentUid": "parent_record_uid"
    }

    def __init__(self, record: Any, logger: Optional[Any] = None,  debug_level: int = 0, fail_on_corrupt: bool = True,
                 agent: Optional[str] = None, **kwargs):

        self.conn = get_connection(**kwargs)

        # This will either be a KSM Record, or Commander KeeperRecord
        self.record = record
        self._dag = None
        self.logger = logger
        self.debug_level = debug_level
        self.fail_on_corrupt = fail_on_corrupt

        self.agent = make_agent("rules")
        if agent is not None:
            self.agent += "; " + agent

    @property
    def dag(self) -> DAG:
        if self._dag is None:

            # Turn auto_save on after the DAG has been created.
            # No need to call it six times in a row to initialize it.
            self._dag = DAG(conn=self.conn,
                            record=self.record,
                            # endpoint=PamEndpoints.DISCOVERY_RULES,
                            graph_id=PamGraphId.DISCOVERY_RULES,
                            auto_save=False,
                            logger=self.logger,
                            debug_level=self.debug_level,
                            fail_on_corrupt=self.fail_on_corrupt,
                            agent=self.agent)
            self._dag.load()

            # Has the status been initialized?
            if not self._dag.has_graph:
                for rule_type_enum in Rules.RULE_TYPE_TO_SET_MAP:
                    rules = self._dag.add_vertex()
                    rules.belongs_to_root(
                        EdgeType.KEY,
                        path=rule_type_enum.value
                    )
                    content = Rules.RULE_TYPE_TO_SET_MAP[rule_type_enum]()
                    rules.add_data(
                        content=content,
                    )
                self._dag.save()

            # The graph exists now, turn on the auto_save.
            self._dag.auto_save = True
        return self._dag

    def close(self):
        """
        Clean up resources held by this Rules instance.
        Releases the DAG instance and connection to prevent memory leaks.
        """
        if self._dag is not None:
            if self.logger:
                self.logger.debug("closing Rules DAG instance")
            self._dag = None
        self.conn = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup."""
        self.close()
        return False

    @staticmethod
    def data_path(rule_type: RuleTypeEnum):
        return f"/{rule_type.value}"

    def get_ruleset(self, rule_type: RuleTypeEnum):
        path = self.data_path(rule_type)
        rule_json = self.dag.walk_down_path(path).content_as_str
        if rule_json is None:
            raise DAGException("Could not get the status data from the DAG.")
        rule_set_class = Rules.RULE_TYPE_TO_SET_MAP[rule_type]
        return rule_set_class.model_validate_json(rule_json)

    def set_ruleset(self, rule_type: RuleTypeEnum, rules: List[Rules]):
        path = self.data_path(rule_type)
        self.dag.walk_down_path(path).add_data(
            content=rules,
        )
        # Auto save should save the data

    def _rule_transaction(self, func: Callable, rule: Optional[RuleItem] = None):
        rule_type = rule.__class__.__name__
        rule_type_enum = Rules.RULE_ITEM_TYPE_MAP.get(rule_type)
        if rule_type_enum is None:
            raise ValueError("rule is not a known rule instance")

        # Get the ruleset and the rule list for the type
        ruleset = self.get_ruleset(rule_type_enum)

        # Call the specialized code
        rules = func(
            r=rule,
            rs=ruleset.rules
        )

        # Sort the rule by priority in asc order.
        ruleset.rules = list(sorted(rules, key=lambda x: x.priority))
        self.set_ruleset(rule_type_enum, ruleset)

    def add_rule(self, rule: RuleItem) -> RuleItem:

        if rule.rule_id is None:
            rule.rule_id = "RULE" + base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip('=')
        if rule.added_ts is None:
            rule.added_ts = int(time())

        def _add_rule(r: RuleItem, rs: List[RuleItem]):
            rs.append(r)
            return rs

        self._rule_transaction(
            rule=rule,
            func=_add_rule
        )

        return rule

    def update_rule(self, rule: RuleItem) -> RuleItem:

        def _update_rule(r: RuleItem, rs: List[RuleItem]):
            new_rule_list = []
            for _r in rs:
                if _r.rule_id == r.rule_id:
                    new_rule_list.append(r)
                else:
                    new_rule_list.append(_r)
            return new_rule_list

        self._rule_transaction(
            rule=rule,
            func=_update_rule
        )

        return rule

    def remove_rule(self, rule: RuleItem):

        def _remove_rule(r: RuleItem, rs: List[RuleItem]):
            new_rule_list = []
            for _r in rs:
                if _r.rule_id != r.rule_id:
                    new_rule_list.append(_r)
            return new_rule_list

        self._rule_transaction(
            rule=rule,
            func=_remove_rule
        )

    def rule_list(self, rule_type: RuleTypeEnum, search: Optional[str] = None) -> List[RuleItem]:
        rule_list = []
        for rule_item in self.get_ruleset(rule_type).rules:
            if search is not None and rule_item.search(search) is False:
                continue
            rule_list.append(rule_item)

        return rule_list

    def get_rule_item(self, rule_type: RuleTypeEnum, rule_id: str) -> Optional[RuleItem]:
        for rule_item in self.rule_list(rule_type=rule_type):
            if rule_item.rule_id == rule_id:
                return rule_item
        return None

    @staticmethod
    def make_action_rule_from_content(content: DiscoveryObject, action: RuleActionEnum, priority: Optional[int] = None,
                                      case_sensitive: bool = True,
                                      shared_folder_uid: Optional[str] = None) -> ActionRuleItem:

        if action == RuleActionEnum.IGNORE:
            priority = -1

        record_fields = Rules.RECORD_FIELD.get(content.record_type)
        if record_fields is None:
            raise ValueError(f"Record type {content.record_type} does not have fields maps.")

        statements = [
            Statement(field="recordType", operator="==", value=content.record_type)
        ]

        for field_label in record_fields:
            if field_label in Rules.OBJ_ATTR:
                attr = Rules.OBJ_ATTR[field_label]
                if not hasattr(content, attr):
                    raise Exception(f"Discovery object is missing attribute {attr}")
                value = getattr(content, attr)
                statements.append(
                    Statement(field=field_label, operator="==", value=value)
                )
            else:
                for field in content.fields:
                    label = field.label
                    if field_label != label:
                        continue

                    value = field.value
                    if value is None or len(value) == 0:
                        continue
                    value = value[0]

                    if label in Rules.BREAK_OUT:
                        for key in Rules.BREAK_OUT[label]:
                            key_value = value.get(key)
                            if key_value is None:
                                continue
                            statements.append(
                                Statement(field=key, operator="==", value=key_value)
                            )
                    else:
                        statements.append(
                            Statement(field=label, operator="==", value=value)
                        )

        return ActionRuleItem(
            enabled=True,
            priority=priority,
            case_sensitive=case_sensitive,
            statement=statements,
            action=action,
            shared_folder_uid=shared_folder_uid
        )

    @staticmethod
    def make_action_rule_statement_str(statement: List[Statement]) -> str:
        statement_str = ""
        for item in statement:
            if statement_str != "":
                statement_str += " and "
            statement_str += item.field + " " + item.operator + " "
            field_type = Rules.RULE_FIELDS.get(item.field).get("type")
            if field_type is None:
                raise ValueError("Unknown field in rule")
            if field_type is str:
                statement_str += f"'{item.value}'"
            elif field_type is bool:
                if value_to_boolean(item.value) is True:
                    statement_str += "true"
                else:
                    statement_str += "false"
            elif field_type is float:
                if int(item.value) == item.value:
                    statement_str += str(int(item.value))
                else:
                    statement_str += str(item.value)
            else:
                raise ValueError("Cannot determine the field type for rule statement.")
        return statement_str
