import docker
import json
import logging
import os
import requests
import socket
import sys
import time

dockerSocketUrl = os.getenv('DOCKER_HOST', "unix://var/run/docker.sock")
defaultDnsRecordTarget = os.getenv('DEFAULT_DNS_RECORD_TARGET', '')
piholeApiToken = os.getenv('PIHOLE_API_TOKEN', "")
piholeApiUrl = os.getenv('PIHOLE_API_URL', "http://pi.hole:8080/admin/api.php")
stateFilePath = os.getenv('STATE_FILE', "/state/pihole.state")
syncInterval = os.getenv('SYNC_INTERVAL_SEC', 30)

client = docker.DockerClient(base_url=dockerSocketUrl)

loggingLevel = logging.getLevelName(os.getenv('LOGGING_LEVEL', "INFO"))
logging.basicConfig(
    level=loggingLevel,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

global globalList
globalList = set()


def ipTest(ip):
    is_ip = False
    try:
        socket.inet_aton(ip)
        is_ip = True
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        logger.debug(message)

    return is_ip, ip


def flushList():
    jsonObject = json.dumps(list(globalList), indent=2)
    with open(stateFilePath, "w") as outfile:
        outfile.write(jsonObject)


def readState():
    fileExists = os.path.exists(stateFilePath)
    if fileExists:
        logger.info("Loading existing state...")
        with open(stateFilePath, 'r') as openfile:
            readList = json.load(openfile)
            for obj in readList:
                logger.info("From file (%s): %s" % (type(obj), obj))
                globalList.add(tuple(obj))
            # globalList = set(readList)
    else:
        logger.info("Loading skipped, no db found.")


def printState():
    logger.debug("State")
    logger.debug("-----------")
    for obj in globalList:
        logger.debug(obj)
    logger.debug("-----------")


def apiCall(endpoint, action, domain=None, target=None):
    if action == "get":
        r = requests.get("%s?auth=%s&%s&action=%s" % (piholeApiUrl, piholeApiToken, endpoint, action))
        if r.json()["data"]:
            success = True
        else:
            success = False
    else:
        if endpoint == "customdns":
            paramName = "ip"
        elif endpoint == "customcname":
            paramName = "target"
        r = requests.get(
            "%s?auth=%s&%s&action=%s&domain=%s&%s=%s" % (piholeApiUrl, piholeApiToken, endpoint, action, domain, paramName, target))
        if r.json()["success"]:
            success = True
        else:
            success = False

    return (success, r.json())


def listExisting():
    logger.debug("Fetching current records...")

    dnsSuccess, dnsResult = apiCall("customdns", "get")
    dns = set([tuple(x) for x in dnsResult["data"]])
    logger.debug("DNS Records: %s" % dns)

    cnameSuccess, cnameResult = apiCall("customcname", "get")
    cname = set([tuple(x) for x in cnameResult["data"]])
    logger.debug("CName Records: %s" % cname)

    logger.debug("done")
    return {"dns": dns, "cname": cname}


def addObject(obj, existingrecords):
    domain = False
    ip = False
    cname = False
    logger.info("Adding: " + str(obj))
    domain = obj[0]
    is_ip, target = ipTest(obj[1])
    logger.debug("domain (%s): %s" % (type(domain), domain))
    logger.debug("target (%s): %s" % (type(target), target))
    logger.debug("is_ip: %s" % (str(is_ip)))
    if is_ip:
        if obj in existingrecords["dns"]:
            success, result = [True, "This record already exists, adding to state."]
            logger.debug(result)
        else:
            success, result = apiCall("customdns", "add", domain, target)
            logger.debug(result)
    else:
        if obj in existingrecords["cname"]:
            success, result = [True, "This record already exists, adding to state."]
            logger.debug(result)
        else:
            success, result = apiCall("customcname", "add", domain, target)
            logger.debug(result)

    if success:
        globalList.add(obj)
        logger.info("Added to global list after success: %s" % (str(obj)))
    else:
        logger.error("Failed to add to list: %s" % (str(result)))


def removeObject(obj, existingrecords):
    domain = False
    ip = False
    cname = False
    logger.info("Removing: " + str(obj))

    domain = obj[0]
    is_ip, target = ipTest(obj[1])
    logger.debug("domain (%s): %s" % (type(domain), domain))
    logger.debug("target (%s): %s" % (type(target), target))
    logger.debug("is_ip: %s" % (str(is_ip)))

    if is_ip:
        if obj not in existingrecords["dns"]:
            success, result = [True, "This record doesn't exist, removing from state."]
            logger.debug(result)
        else:
            success, result = apiCall("customdns", "delete", domain, target)
            logger.debug(result)
    else:
        if obj not in existingrecords["cname"]:
            success, result = [True, "This record doesn't exist, removing from state."]
            logger.debug(result)
        else:
            success, result = apiCall("customcname", "delete", domain, target)
            logger.debug(result)

    if success:
        globalList.remove(obj)
        logger.info("Removed from global list after success: %s" % (str(obj)))
    else:
        logger.error("Failed to remove from list: %s" % (str(result)))


def handleList(newGlobalList, existingrecords):
    toAdd = set([x for x in newGlobalList if x not in globalList])
    toRemove = set([x for x in globalList if x not in newGlobalList])
    toSync = set([x for x in globalList if ((x not in existingrecords["dns"]) and (x not in existingrecords["cname"]))])

    if len(toAdd) > 0:
        logger.debug("These are labels to add: %s" % toAdd)
        for add in toAdd:
            addObject(add, existingrecords)

    if len(toRemove) > 0:
        logger.debug("These are labels to remove: %s" % toRemove)
        for remove in toRemove:
            removeObject(remove, existingrecords)

    if len(toSync) > 0:
        logger.debug("These are labels to sync: %s" % toSync)
        for sync in (toSync - toAdd - toRemove):
            addObject(sync, existingrecords)

    printState()
    flushList()


if __name__ == "__main__":
    if piholeApiToken == "":
        logger.warning("pihole token is blank, Set a token environment variable PIHOLE_TOKEN")
        sys.exit(1)

    else:
        readState()

        while True:
            logger.debug("Listing containers...")
            containers = client.containers.list()
            globalListBefore = globalList.copy()
            newGlobalList = set()
            existingrecords = listExisting()

            for container in containers:
                host_ip = container.labels.get('pihole.dns.target.override', defaultDnsRecordTarget)
                for key, value in container.labels.items():
                    if ((key.startswith('traefik.http.routers.') or key.startswith('traefik.https.routers.'))
                            and key.endswith('.rule')):
                        host_directives = value.split('||')
                        for directive in host_directives:
                            if 'Host(' in directive:
                                directive = directive.split('Host(')[-1].rstrip(')\'" ')
                                domains = [domain.strip('` ,') for domain in directive.split(',') if domain.strip()]
                                for domain in domains:
                                    newGlobalList.add(tuple([domain, host_ip]))

            handleList(newGlobalList, existingrecords)
            logger.debug("Run sync")

            time.sleep(syncInterval)
