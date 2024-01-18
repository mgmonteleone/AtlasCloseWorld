import datetime
import logging

import atlasapi.whitelist
from atlasapi.atlas import Atlas

from atlasapi.projects import Project
import ipaddress
import os
import humanize
from typing import Iterable, Tuple, List

import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.ERROR)

MAX_ADDRESSES = 16777216
atlas_client = Atlas(user=os.getenv("ATLAS_KEY"), password=os.getenv("ATLAS_SECRET"), group=os.getenv("ATLAS_GROUP"))


class Results:
    def __init__(self, status: int, message: str, data: dict):
        self.data = data
        self.message = message
        self.status = status


class AllowListCheck:
    def __init__(self, org_id: str, max_addresses: int = ipaddress.ip_network('10.0.0.0/8').num_addresses):
        self.max_addresses = max_addresses
        self.org_id = org_id
        self.org_client = Atlas(user=os.getenv("ATLAS_KEY"), password=os.getenv("ATLAS_SECRET"))

    @property
    def projects_list(self) -> Iterable[Project]:
        """Returns the list of all projects for the given Organization.


        :returns
                project_list(Iterable[Project]) : Iterable of Project options
        """
        project_list = self.org_client.Organizations.get_all_projects_for_org(self.org_id)
        return project_list

    def get_access_lists(self) -> List[Tuple[Project, atlasapi.whitelist.WhitelistEntry]]:
        list_entries: list = list()
        violating_entries: list = list()
        each_allow_list: atlasapi.whitelist.WhitelistEntry
        each_project: Project
        list_entries = list()
        for each_project in self.projects_list:
            atlas_client = Atlas(user=os.getenv("ATLAS_KEY"), password=os.getenv("ATLAS_SECRET"),
                                 group=each_project.id)
            for each_allow_list in atlas_client.Whitelist.get_all_whitelist_entries():
                list_entries.append((each_project, each_allow_list))

        return list_entries

    @property
    def allow_lists_all(self) -> Iterable[Tuple[Project, atlasapi.whitelist.WhitelistEntry]]:
        for each in self.get_access_lists():
            yield each

    def allow_lists_violating(self, return_all=False) -> Iterable[str]:
        """Key method for checking the Organizations access lists.

        Finds all projects for the organization and checks the "size" of each entry. ALways checks for 0.0.0.0/0


        """
        for each in self.allow_lists_all:
            try:
                cidrstr: str = each[1].cidrBlock
                cidrobj = ipaddress.ip_network(cidrstr)

                if cidrstr == '0.0.0.0/0':
                    result = Results(0,
                                     message=f"❌For Project {each[0].name} The subnet ({cidrobj.with_prefixlen}) is too wide ({humanize.intword(cidrobj.num_addresses)} > {humanize.intword(MAX_ADDRESSES)})"
                                     , data=dict(project_data=each[0].__dict__, entry=each[0].__dict__)
                                     )

                elif cidrobj.num_addresses > self.max_addresses and cidrobj.is_private is False:
                    result = Results(0,
                                     message=f"❌For Project {each[0].name} The subnet ({cidrobj.with_prefixlen}) is too wide ({humanize.intword(cidrobj.num_addresses)} > {humanize.intword(MAX_ADDRESSES)})"
                                     , data=dict(project_data=each[0].__dict__, entry=each[0].__dict__)
                                     )

                else:

                    if return_all:
                        result = Results(status=1,
                                         message=f"✅For Project {each[0].name} The subnet {cidrobj} passes check...",
                                         data=dict(project_data=each[0].__dict__, entry=each[0].__dict__))
                    else:
                        result = None

            except (AttributeError, ValueError):
                result = Results(status=1,
                                 message=f"‼️For Project {each[0].name}: The subnet {each[1].cidrBlock} mask is not "
                                         f"not valid!",
                                 data=dict(project_data=each[0].__dict__, entry=each[0].__dict__))

            if result:
                yield result
