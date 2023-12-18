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

    def filter_check(self, data: dict) -> bool:
        "Returns true if we should include it"
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
