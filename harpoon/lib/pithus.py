import json

import requests


class PithusError(Exception):
    def __init__(self, message, **kwargs):
        Exception.__init__(self, message)
        self.message = message


class PithusQuotaExceeded(PithusError):
    pass


class Pithus(object):
    def __init__(self, config=None):
        self.url = config['url']
        self.api_key = config['key']
        self.headers = {
            "User-Agent": "Harpoon (https://github.com/Te-k/harpoon)",
        }
        if self.api_key:
            self.headers["Authorization"] = "Token " + self.api_key
        else:
            PithusError(
                "Missing token, visit beta.pithus.org/hunting to retrieve it")

    def handle_request(self, r):
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            raise PithusError("Report not found")
        elif r.status_code == 453:
            raise PithusQuotaExceeded("Quota exceeded")
        elif r.status_code != 200 or r.status_code != 453:
            raise PithusError(r)
        else:
            raise PithusError(
                'Invalid HTTP Code returned: {}'.format(r.status_code))

    def handle_error(self, error_code):
        if error_code == 2:
            return "Success"
        elif error_code == -1:
            return "Error"
        elif error_code == 1:
            return "Running"
        else:
            return "Unknow status"

    def pretty_print(self, result, result_type):
        print("######## Pithus results")
        print("")

        if result_type == 'search':
            for res in result:
                print("[*] Result for " + self.url + "report/" +
                      res["source"]["sha256"])
                print("App name      ", res["source"]["app_name"])
                print("Handle        ", res["source"]["handle"])
                print("Sha256        ", res["source"]["sha256"])
                print("Frosted       ", res["source"]
                      ["frosting_data"]["is_frosted"])
                print("Uploaded at   ", res["source"]["uploaded_at"])
                print("Signed        ", res["source"]["is_signed"])
                if "quark" in res["source"]:
                    print("Quark result  ", res["source"]["quark"]["threat_level"])

                if res["score"] is not None:
                    print("Score:         ", res["score"])

                if "highlight" in res:
                    if len(res["highlight"]) > 0:
                        print("")
                        print("---- Search matches:")
                        for matches_key in res["highlight"]:
                            for value in res["highlight"][matches_key]:
                                print("{} - {}".format(matches_key, value.replace("<mark>", "").replace("</mark>", "")))

                if len(res["source"]["features"]) > 0:
                    print("")
                    print("---- Features:")
                    for feat in res["source"]["features"]:
                        print(feat)

                if "vt" in res["source"]:
                    print("")
                    print("----- VirusTotal:")
                    print("VT malicious   ", res["source"]["vt"]["malicious"])
                    print("VT suspicious  ", res["source"]["vt"]["suspicious"])
                    print("VT undetected  ", res["source"]["vt"]["undetected"])

                print("")
                print("")

        elif result_type == 'status':
            print("APKiD analysis status            ",
                  self.handle_error(result['apkid_analysis']))
            print("SSDeep analsysis status          ",
                  self.handle_error(result['ssdeep_analysis']))
            print("Class extracted                  ",
                  self.handle_error(result['extract_classes']))
            print("Quark analysis status            ",
                  self.handle_error(result['quark_analysis']))
            print("MobSF analysis status            ",
                  self.handle_error(result['mobsf_analysis']))
            print("VirusTotal analsysis status      ",
                  self.handle_error(result['vt_analysis']))
            print("Malware Bazaar analsysis status  ",
                  self.handle_error(result['malware_bazaar_analysis']))
            print("")
            print("Analysis date                    ", result['analysis_date'])

        elif result_type == 'report':
            print("--------- General information:")
            print("Handle             ", result['handle'])
            print("App name           ", result['app_name'])
            print("Version name       ", result['version_name'])
            print("Version code       ", result['version_code'])
            print("Uploaded at        ", result['uploaded_at'])
            print("Main activity      ", result['main_activity'])
            print("Target SDK version ", result["target_sdk_version"])
            print("Frosted            ", result["frosting_data"]["is_frosted"])
            print("")

            if len(result['certificates']) > 0:
                print("--------- Certificates:")
                for certificate in result['certificates']:
                    print(json.dumps(certificate, indent=4))
                print("")

            if len(result['activities']) > 0:
                print("--------- Activities:")
                for activity in result['activities']:
                    print(json.dumps(activity, indent=4))
                print("")

            if len(result['permissions']) > 0:
                print("-------- Permissions:")
                for permission in result['permissions']:
                    print(json.dumps(permission, indent=4))
                print("")

            if len(result['providers']) > 0:
                print("------- Providers:")
                for provider in result['providers']:
                    print(json.dumps(provider, indent=4))
                print("")

            if len(result['services']) > 0:
                print("------ Services:")
                for service in result['services']:
                    print(json.dumps(service, indent=4))
                print("")

            if len(result['domains_analysis']) > 0:
                print("------- Domains found:")
                for domain in result['domains_analysis']:
                    print(json.dumps(domain['_name'], indent=4))
                print("")

        else:
            raise PithusError("Something went wrong... Try again, maybe?")

    def _get(self, url, result_type):
        r = requests.get(url, headers=self.headers)
        return self.handle_request(r)
        # return self.pretty_print(url, res, result_type)

    def _post(self, url, params, result_type):
        r = requests.post(url, json=params, headers=self.headers)
        res = self.handle_request(r)
        return self.pretty_print(url, res, result_type)

    def report(self, query):
        return self._get(self.url + "report/" + query, 'report')

    def status(self, query):
        return self._get(self.url + "status/" + query, 'status')

    def search(self, query):
        params = {
            "q": query,
        }
        return self._post(self.url + "search/", params, 'search')

    def upload(self, data):
        params = {
            "file": data,
        }
        url = self.url + "/upload"
        res = requests.post(url, files=params, headers=self.headers)

        if res.status_code == 200:
            print("Upload successful!")
            print(self.url + "/report/" +
                  res.json()['file_sha256'])
        else:
            print(res.status_code)
