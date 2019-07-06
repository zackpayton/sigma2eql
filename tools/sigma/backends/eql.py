# Output backends for sigmac
# Copyright 2019 Zack Payton @zackpayton

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
from .base import SingleTextQueryBackend

# test cmd
# python sigma/tools/sigmac --target eql --config sigma/tools/config/eql.yml sigma/rules/windows/sysmon/sysmon_lsass_memdump.yml


class EQLQueryStringBackend(SingleTextQueryBackend):
    """Converts Sigma rule into EQL query string. Only searches, no aggregations."""
    identifier = "eql"
    active = True
    config_required = True

    reEscape = re.compile("([+\\-!(){}\\[\\]^\"~/]|(?<!\\\\)\\\\(?![*?\\\\])|&&|\\|\\|)")
    reWildcard = re.compile(".*\*.*").search
    reClear = None
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "%s"
    listExpression = "in (%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "NOT _exists_:%s"
    notNullExpression = "_exists_:%s"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = False

    log_source = None
    product = None
    service = None
    sysmon_yaml = None


    def generateBefore(self, parsed):
        if self.product == "windows":
            if self.service == "security":
                return "security where "
            if self.service == "sysmon":
                if self.sysmon_id == 1:
                    return "process_create where "
                if self.sysmon_id == 2:
                    return "file where "
                if self.sysmon_id == 3:
                    return "network where "
                if self.sysmon_id == 4:
                    return "sysmon_service_state_changed where "
                if self.sysmon_id == 5:
                    return "process_terminate where "
                if self.sysmon_id == 6:
                    return "driver_load where "
                if self.sysmon_id == 7:
                    return "module_load where "
                if self.sysmon_id == 8:
                    return "create_remote_thread where "
                if self.sysmon_id == 9:
                    return "raw_access_read where "
                if self.sysmon_id == 10:
                    return "process_access where "
                if self.sysmon_id == 11:
                    return "file_create where "
                if self.sysmon_id in [12, 13, 14]:
                    return "registry_event where "
                if self.sysmon_id == 15:
                    return "file_create_stream_hash where "
                if self.sysmon_id == 16:
                    return "sysmon_config_state_changed where "
                if self.sysmon_id in [17, 18]:
                    return "pipe_event where "
                if self.sysmon_id in [19, 20, 21]:
                    return "wmi_event where "


    def generate(self, sigmaparser):
        try:
            self.log_source = sigmaparser.parsedyaml['logsource']
            self.product = self.log_source['product']
            self.service = self.log_source['service']
            if self.service == "sysmon":
                self.sysmon_id = sigmaparser.parsedyaml['detection']['selection']['EventID']
        except:
            pass

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after =  self.generateAfter(parsed)

            result = ""

            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after
            return result
    def generateNode(self, node):
        """ here we exclude event ID because of the nature
            of EQL, the type of event is derived from the
            initially specified event_type as specified
            here: https://github.com/endgameinc/eql/blob/master/eql/etc/schema.json"""
        #print("Type: {} Node: {}".format(type(node), node))
        if type(node) is tuple and len(node) == 2 and 'event_id' in node:
            return None
        return super().generateNode(node)

    def generateMapItemListNode(self, fieldname, value):
        #print("generateMapItemListNode: f:{} v:{}".format(fieldname, value))
        return self.mapListValueExpression % (fieldname, self.generateNode(value))

    def listContainsEQLWildcards(self, value_list):
        for i in value_list:
            if self.reWildcard(i):
                return True
        return False

    def generateMapItemNode(self, node):
        fieldname, value = node
        if type(value) is list and self.listContainsEQLWildcards(value):
            lv = ', '.join([f'"{v}"' for v in value])
            return f"wildcard({fieldname}, {lv})"

        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list)\
                or self.mapListsSpecialHandling == True and type(value) in (str, int):
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))
