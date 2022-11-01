import requests

class SalesforceReport:
    """
    Salesforce Report 
    """

    def __init__(self, report_id=None, instance_url=None, access_token=None, api_version='v35.0'):
        self.report_id = report_id
        self.instance_url = instance_url
        self.access_token = access_token
        self.report_path = '/services/data/{}/analytics'.format(api_version)

    def _get_request_headers(self):
        return {"Accept": "application/json",
                "Content-type": "application/json; charset=UTF-8",
                "Authorization": "Bearer " + self.access_token}

    def _get_metadata(self, url):
        return requests.get(url + '/describe', headers=self._get_request_headers()).json()

    def _get_report_filtered(self, url, filters):
        metadata_url = url.split('?')[0]
        metadata = self._get_metadata(metadata_url)
        for report_filter in filters:
            metadata["reportMetadata"]["reportFilters"].append(report_filter)

        return requests.post(url, headers=self._get_request_headers(), json=metadata).json()

    def _get_report_all(self, url):
        return requests.post(url, headers=self._get_request_headers()).json()

    def get_report(self, filters=None, details=True):
        """
        Return the full JSON content of a Salesforce report, with or without filters.

        Parameters
        ----------
        report_id: string
            Salesforce Id of target report
        filters: dict {field: filter}, optional
        details: boolean, default True
            Whether or not detail rows are included in report output

        Returns
        -------
        report: JSON
        """
        details = 'true' if details else 'false'
        url = '{}{}/reports/{}?includeDetails={}'.format(self.instance_url, self.report_path, self.report_id, details)

        if filters:
            return self._get_report_filtered(url, filters)
        else:
            return self._get_report_all(url)

    def get_dashboard(self, dashboard_id):
        url = '{}{}/dashboards/{}/'.format(self.instance_url, self.report_path, dashboard_id)
        return requests.get(url, headers=self._get_request_headers()).json()
