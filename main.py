import os

from AtlasCloseWorld import AllowListCheck, Results

ORG_ID = os.getenv('ORG_ID')

if __name__ == '__main__':
    check = AllowListCheck(org_id=ORG_ID)
    each: Results
    for each in check.allow_lists_violating(return_all=False):
        print(each.message)
