def parse(csv_data: str) -> list[list[str]]:
    return [csv_line.split(",") for csv_line in \
                                  csv_data
                                    .removeprefix("\n")
                                    .removesuffix("\n")
                                    .split("\n")]