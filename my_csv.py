""" 
   _____         __              ______ ______ ______
  / ___/ ____   / /____ _ _____ / ____//_  __// __  /
  \__ \ / __ \ / // __ `// ___// /      / /  / /_/ /
 ___/ // /_/ // // /_/ // /   / /___   / /  / ____/ 
/____/ \____//_/ \__,_//_/    \____/  /_/  /_/      
"""

def parse(csv_data: str) -> list[list[str]]:
    return [csv_line.split(",") for csv_line in \
                                  csv_data
                                    .removeprefix("\n")
                                    .removesuffix("\n")
                                    .split("\n")]