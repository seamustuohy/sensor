"""Decompose Probe Requests."""


class ProbeReqDecomposer(object):
    """Probe Request Decomposer."""

    @classmethod
    def decompose(cls, scan_document):
        """Decompose a Probe event.

        Args:
            scan_document (dict): Geo json from GPS device.

        Returns:
            list: One two-item tuple in list.  Position 0 is `probereq`, position 1
                is a single probe request.  If the scan doesn't validate, an
                empty list is returned.
        """
        results_set = [("probereq", scan_document)]
        if not ProbeReqDecomposer.scan_document_is_valid(scan_document):
            return []
        else:
            return results_set

    @classmethod
    def scan_document_is_valid(cls, scan_document):
        """Validate the scan document."""
        is_valid = False
        if ("SSID" in scan_document) and ("MAC_addr" in scan_document):
            is_valid = True
        return is_valid
