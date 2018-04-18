'''
Created on Oct 19, 2017

@author: cash.chang
'''
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import json
import logging
import logging.config
import os
import pickle
import posixpath
import random
import socket
import string
from time import sleep

import requests
from requests.exceptions import ConnectionError, HTTPError
import requests.utils

min_poll_interval = 60

logging.basicConfig(level=logging.INFO,
        format='%(asctime)s %(levelname)s %(module)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S")


def genId(size=10, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class Const:
    cmd = "command"
    build = "build"
    check = "check"
    stop = "stop"
    login = "login"
    host = "host"
    job = "job"
    user = "user"
    pwd = "pwd"
    token = "token"
    parms = "parms"
    cause = "cause"
    get_build_number = "get_build_number"
    get_build_status = "get_build_status"
    poll = "poll"
    poll_interval = "poll_interval"
    build_number = "build_number"
    build_number_key = "JENKINS_BUILD_NUMBER"
    check_status_key = "JENKINS_BUILD_STATUS"
    config_file = "config_file"
    request_timeout = "timeout"
    default_timeout = 10
    quiet_period = "quiet_period"
    default_quiet_period = 5    
    retry_count = "retry_count"
    default_retry_count = 5


class JenkinsTrigger(object):
    
    def __init__(self, **kwds):
        self.logger = logging.getLogger("jks")
        self.targetFile = ""
        self.host = kwds[Const.host][:-1] if kwds[Const.host].endswith("/") else kwds[Const.host] 
        self.job = kwds[Const.job]
        self.user = kwds[Const.user]
        self.pwd = kwds[Const.pwd]
        self.cfg = kwds[Const.config_file]
        
        userHome = os.path.expanduser("~")
        self.jksSessinHome = os.path.join(userHome, ".jkssesion")
        self.cookieFile = os.path.join(self.jksSessinHome, "{}_cookies".format(self.user))
        self.isCsrf = None
        
        self.session = requests.Session()
        
        if self.cfg:
            with open(self.cfg, 'r') as f:
                cfg = json.load(f, encoding='utf8')
                if not self.user:
                    self.user = cfg[Const.user]
                if not self.pwd:
                    self.pwd = cfg[Const.pwd]
        
        if self.user and self.pwd:
            self.__login(**kwds)
    
    def __updateCsrf(self, **kwds):
        try:
            url = "{}/crumbIssuer/api/json".format(self.host)
            
            res = self.__get(url, **kwds)
            
            if res.status_code == 404:
                self.logger.info("The CSRF protection was disabled by the server.")
                self.isCsrf = False
                return
            else:
                res.raise_for_status()
            
            crumb = res.json()
            self.session.headers.update({crumb["crumbRequestField"]: crumb["crumb"]})
            self.isCsrf = True
        
        except:
            self.logger.error("Fail to update CSRF!")
            raise

    def __checkSession(self, **kwds):
        if not os.path.exists(self.jksSessinHome):
            os.makedirs(self.jksSessinHome)
            
        if os.path.exists(self.cookieFile):
            try:
                with open(self.cookieFile) as f:
                    cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
                    self.session.cookies = cookies
                    
                    url = posixpath.join(self.host, "me", "api", "json")
                    res = self.__get(url, **kwds)
                    res.raise_for_status()
                    
                    return res.json()["id"] == self.user
                        
        #             self.session = requests.session(cookies=cookies)
            except:
                self.logger.exception("fail to load cookie, login directly...")
                return False
        else:
            return False
    
    def __post(self, url, data={}, **kwds):
        
        if self.isCsrf == None or self.isCsrf:
            self.__updateCsrf(**kwds)
            
        return self.session.post(url, data=data, timeout=kwds.get(Const.request_timeout, Const.default_timeout))
    
    def __get(self, url, **kwds):
        return self.session.get(url, timeout=kwds.get(Const.request_timeout, Const.default_timeout))

    def __login(self, **kwds):
        
        if self.__checkSession(**kwds):
            self.logger.info("reusing session...") 
            return
        
        login = posixpath.join(self.host, "j_acegi_security_check")        
        self.logger.info("login from: [%s]... ", socket.gethostname())
        
        res = self.session.post(login, data={'j_password':  self.pwd, 'j_username': self.user},
                                timeout=kwds.get(Const.request_timeout, Const.default_timeout))
        res.raise_for_status()
        
        with open(self.cookieFile, 'w') as f:
            pickle.dump(requests.utils.dict_from_cookiejar(self.session.cookies), f)
        
        self.logger.info("login successfully!")

    def __checkParameter(self, **kwds):
        # to compatible with old version < 1.6x
        url = "{url}".format(url=posixpath.join(self.host, "job", self.job, "api", "json"))
        res = self.__get(url, **kwds)
        res.raise_for_status()
        
        job_config = res.json()
        for prop in job_config['property']:
            if prop.get("_class", "") == "hudson.model.ParametersDefinitionProperty" or prop.get("parameterDefinitions", ""):
                return True
        
        return False
        
    def check(self, **kwds):
        url = "{url}?tree=building,result".format(url=posixpath.join(self.host, "job", self.job, str(kwds[Const.build_number]), "api", "json"))
        interval = min_poll_interval if kwds[Const.poll_interval] < min_poll_interval else kwds[Const.poll_interval] 
        retry = 0
        result = {'building': True}
        
        while result['building']:
            try:
                getStatusDyn = "{fix}&rid={id}".format(fix=url, id=genId())
                res = self.__get(getStatusDyn, **kwds)
                res.raise_for_status()
                result = res.json()
                
                if result['building']:
                    self.logger.info("%s: Building...", Const.check_status_key)                    
                else:
                    self.logger.info("%s: %s", Const.check_status_key, result['result'])
                    break
                
                if kwds[Const.poll]:
                    sleep(interval)
                else:
                    break
                    
            except ConnectionError as e:
                retry += 1
                if retry >= 2:
                    raise e
                self.logger.exception("unknown connection error, session timeout, etc")
                self.logger.info("try to reconnect...")
                self.__login()

    def build(self, **kwds):
        
        buildTerm = "buildWithParameters" if self.__checkParameter(**kwds) else "build"
        
        buildUrl = "{url}?token={api}{cause}".format(url=posixpath.join(self.host, "job", self.job, buildTerm),
                                          api=kwds[Const.token],
                                          cause="&cause={}".format(requests.utils.quote(kwds[Const.cause], safe="")) if kwds.get(Const.cause, "") else "")
        
        data = {}
        for parm in kwds[Const.parms]:
            pair = parm.split("=")
            data[pair[0]] = pair[1]
                
        res = self.__post(buildUrl, data=data, **kwds)
        res.raise_for_status()
        self.logger.info("successfully triggered")
        
        if kwds.get(Const.poll, False) or kwds[Const.get_build_number]:
            locate = res.headers.get("Location", None)
            sleep(kwds.get(Const.quiet_period, Const.default_quiet_period) + 1)  # greater than the jenkins default quiet period
            if not locate:
                raise Exception("Fail to get queue id!")
            
            jobNumber = -1
            retry_cnt = kwds.get(Const.retry_count, Const.default_retry_count)
            for i in range(retry_cnt):
                result = ""
                try:
                    """
                    1. inactive items in the build queue are garbage collected after few minutes, so you should retrieve build id ASAP
                    2. by default it takes few seconds between item is added to the queue until it gets build id. 
                       During this time executable and canceled attributes will be missing and why will be not null. 
                       You can change this behavior in "Advanced Project Options" of your job config by modifying "Quiet period" setting 
                       or in the jenkins global configuration.
                    """
                    getHist = "{url}?rid={id}".format(url=posixpath.join(locate, "api", "json"), id=genId())
                    res = self.__get(getHist, **kwds)
                    res.raise_for_status()            
                
                    result = res.json()
                    if "executable"in result and "number" in result['executable']:
                        jobNumber = result['executable']["number"]
                        self.logger.info("%s: %s", Const.build_number_key, jobNumber)
                        break
                    else:
                        self.logger.info("still waiting for build id generation...: %s\n%s", result["why"], result)
                        sleep(1)
                    
                except:
                    if result:
                        try:                            
                            self.logger.warning("failed at get build number: %s", json.dumps(result, indent=3,))
                        except:
                            self.logger.exception("fail to pretty dump result: %s", result)
                    self.logger.exception("retry %s ...", i + 1)
                    sleep(1)
                    if i == retry_cnt - 1:
                        raise
                    
            if jobNumber == -1:
                raise Exception("Something wrong with job number[{}] please check it!".format(jobNumber))
            
            if kwds.get(Const.poll, False) or kwds[Const.get_build_status]:   
                kwds[Const.build_number] = jobNumber
                self.check(**kwds)
    
    def stop(self, **kwds):
        
        build_number = kwds[Const.build_number]
        buildUrl = posixpath.join(self.host, "job", self.job, build_number)
        
        try:  # safely abort
            url = posixpath.join(buildUrl, "stop")
            result = self.__post(url, {}, **kwds)
            result.raise_for_status()
            
        except HTTPError as e:
            self.logger.error("fail to safely stop %s: %s", buildUrl, e)
            try:
                url = posixpath.join(buildUrl, "term")
                result = self.__post(url, **kwds)
                result.raise_for_status()
                
            except HTTPError as ex:
                self.logger.error("fail to soft kill %s: %s", buildUrl, ex)
                try:
                    url = posixpath.join(buildUrl, "kill")
                    result = self.__post(url, **kwds)
                    result.raise_for_status()
                    
                except HTTPError as exp:
                    self.logger.error("fail to hard kill %s: %s", buildUrl, exp)
                    raise exp
        
        self.logger.info("Successfully stopped: %s-%s!", self.job, build_number)


if __name__ == '__main__':
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    
    parser.add_argument("-u", "--user", dest=Const.user, action="store", help="specify the jenkins job executor", default="")
    parser.add_argument("-p", "--pwd", dest=Const.pwd, action="store", help="specify the password or api token for your account", default="")
    parser.add_argument("-c", "--config-file", dest=Const.config_file, action="store",
                        help='specify the json configuration path of user & password, ex: {"user": "xxx", "pwd": "xxx"}, this setting will be overridden if you specify the -u or -p.',
                        default="")
    parser.add_argument("-t", "--timeout", dest=Const.request_timeout, action="store", type=int,
                        help='specify the timeout for http requests', default=Const.default_timeout)
    parser.add_argument("-q", "--quiet-period", dest=Const.quiet_period, action="store", type=int,
                        help='specify the quiet period set in jenkins for the job', default=Const.default_quiet_period)
    parser.add_argument("-r", "--retry-count", dest=Const.retry_count, action="store", type=int,
                        help='specify the retry count when requests failed', default=Const.default_retry_count)
    parser.add_argument(Const.host, action="store", help="specify the jenkins host url. ex: http://jenkins_host:8080",)
    parser.add_argument(Const.job, action="store", help="specify the jenkins job name.",)
    
    subparsers = parser.add_subparsers(dest=Const.cmd, title='sub-commands', description='valid sub-commands', help='actions you can use')
    
    buildParser = subparsers.add_parser(Const.build, help="build job.", formatter_class=ArgumentDefaultsHelpFormatter)
    buildParser.add_argument("-t", "--token" , dest=Const.token, action="store", default="",
                             help="specify the remote token for build job, maybe unnecessary in old jenkins version, but necessary in most jenkins nowadays ",)    
    buildParser.add_argument("-p", "--param" , nargs="*", dest=Const.parms, action="store", help="specify the parameters in key-value pair, ex: a=b ", default=[])
    buildParser.add_argument("-c", "--cause", dest=Const.cause, action="store", help="specify notes for remote build causes which will be shown on Jenkins ", default="")
    buildParser.add_argument("--get-build-number" , dest=Const.get_build_number, action="store_true", help="specify whether to show build number ", default=False)
    buildParser.add_argument("--get-build-status" , dest=Const.get_build_status, action="store_true", help="specify whether to show build status", default=False)
    buildParser.add_argument("--poll" , dest=Const.poll, action="store_true", help="return until job is done", default=False)
    buildParser.add_argument("--poll-interval" , dest=Const.poll_interval, action="store", type=int,
                             help="polling interval in seconds while checking job status, at least 60", default=min_poll_interval)
    
    checkParser = subparsers.add_parser(Const.check, help="check job status.", formatter_class=ArgumentDefaultsHelpFormatter)
    checkParser.add_argument("--poll" , dest=Const.poll, action="store_true", help="return until job is done", default=False)
    checkParser.add_argument("--poll-interval" , dest=Const.poll_interval, action="store", type=int,
                             help="polling interval in seconds while checking job status, at least 60", default=min_poll_interval)   
    checkParser.add_argument(Const.build_number, action="store", help="specify the build number to be checked. ", default=False)
    
    stopParser = subparsers.add_parser(Const.stop, help="safely stop remote jobs.", formatter_class=ArgumentDefaultsHelpFormatter)   
    stopParser.add_argument(Const.build_number, action="store", help="specify the build number to be aborted. ")
    
    args = parser.parse_args()
    
    args = args.__dict__
    
    jt = JenkinsTrigger(**args)
    
    method = getattr(jt, args[Const.cmd])
    method(**args)
    
