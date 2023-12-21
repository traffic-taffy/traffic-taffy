class Output:
    def __init__(self, report, options={}):
        self.report = report
        self.output_options = options

    @property
    def report(self):
        return self._report

    @report.setter
    def report(self, new_report):
        self._report = new_report

    @property
    def output_options(self):
        return self._output_options

    @output_options.setter
    def output_options(self, new_output_options):
        self._output_options = new_output_options

    def output(self, report=None):
        if not report:
            report = self.report
        contents = report.contents

        first_of_anything: bool = True

        for key in sorted(contents):
            reported: bool = False

            if (
                self.output_options.get("match_string") is not None
                and self.output_options["match_string"] not in key
            ):
                continue

            # TODO: we don't do match_value here?

            for subkey, data in sorted(
                contents[key].items(), key=lambda x: x[1]["delta"], reverse=True
            ):
                if not self.filter_check(data):
                    continue

                # print the header
                if not reported:
                    if first_of_anything:
                        self.output_start(report)
                        first_of_anything = False

                    self.output_new_section(key)
                    reported = True

                data["delta"]

                self.output_record(key, subkey, data)

        self.output_close()

    def output_new_section(self, key):
        return

    def output_close(self):
        return

    def filter_check(self, data: dict) -> bool:
        "Return true if we should include it."
        delta: float = data["delta"]
        total: int = data["total"]

        if self.output_options["only_positive"] and delta <= 0:
            return False

        if self.output_options["only_negative"] and delta >= 0:
            return False

        if (
            not self.output_options["print_threshold"]
            and not self.output_options["minimum_count"]
        ):
            # always print
            return True

        if (
            self.output_options["print_threshold"]
            and not self.output_options["minimum_count"]
        ):
            # check output_options["print_threshold"] as a fraction
            if abs(delta) > self.output_options["print_threshold"]:
                return True
        elif (
            not self.output_options["print_threshold"]
            and self.output_options["minimum_count"]
        ):
            # just check output_options["minimum_count"]
            if total > self.output_options["minimum_count"]:
                return True
        else:
            # require both
            if (
                total > self.output_options["minimum_count"]
                and abs(delta) > self.output_options["print_threshold"]
            ):
                return True

        return False
