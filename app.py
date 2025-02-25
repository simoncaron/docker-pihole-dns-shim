import docker
import json
import logging
import os
import requests
import socket
import sys
import time
from base64 import b64encode

# Environment variables
dockerSocketUrl = os.getenv('DOCKER_HOST', "unix://var/run/docker.sock")
defaultDnsRecordTarget = os.getenv('DEFAULT_DNS_RECORD_TARGET', '')
adguardUsername = os.getenv('ADGUARD_USERNAME', "")
adguardPassword = os.getenv('ADGUARD_PASSWORD', "")
adguardApiUrl = os.getenv('ADGUARD_API_URL', "http://adguard:3000/control")
stateFilePath = os.getenv('STATE_FILE', "/state/adguard.state")

# Initialize Docker client
client = docker.DockerClient(base_url=dockerSocketUrl)

# Configure logging
loggingLevel = logging.getLevelName(os.getenv('LOGGING_LEVEL', "INFO"))
logging.basicConfig(
    level=loggingLevel,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global state
global globalList
globalList = set()
# Container records mapping (container_id -> set of records)
container_records = {}

def get_auth_header():
    """Generate Basic Auth header for AdGuard Home API"""
    if not adguardUsername or not adguardPassword:
        logger.error("AdGuard Home credentials not set")
        sys.exit(1)
    credentials = f"{adguardUsername}:{adguardPassword}"
    encoded = b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}

def ipTest(ip):
    """Test if a string is a valid IP address"""
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
    """Save current state to file"""
    jsonObject = json.dumps(list(globalList), indent=2)
    with open(stateFilePath, "w") as outfile:
        outfile.write(jsonObject)

def readState():
    """Read state from file"""
    fileExists = os.path.exists(stateFilePath)
    if fileExists:
        logger.info("Loading existing state...")
        with open(stateFilePath, 'r') as openfile:
            readList = json.load(openfile)
            for obj in readList:
                logger.info("From file (%s): %s" % (type(obj), obj))
                globalList.add(tuple(obj))
    else:
        logger.info("Loading skipped, no db found.")

def printState():
    """Print current state for debugging"""
    logger.debug("State")
    logger.debug("-----------")
    for obj in globalList:
        logger.debug(obj)
    logger.debug("-----------")

def listExisting():
    """Fetch current DNS rewrites from AdGuard Home"""
    try:
        response = requests.get(
            f"{adguardApiUrl}/rewrite/list",
            headers=get_auth_header()
        )
        response.raise_for_status()
        
        rewrites = response.json()
        existing = set()
        for rewrite in rewrites:
            existing.add(tuple([rewrite['domain'], rewrite['answer']]))
        
        logger.debug(f"Existing DNS rewrites: {existing}")
        return existing
    except Exception as e:
        logger.error(f"Failed to fetch DNS rewrites: {str(e)}")
        return set()

def addObject(obj, existing):
    """Add a DNS rewrite to AdGuard Home"""
    domain, target = obj
    logger.info(f"Adding: {domain} -> {target}")

    if obj in existing:
        logger.debug("This record already exists, adding to state.")
        globalList.add(obj)
        return

    try:
        response = requests.post(
            f"{adguardApiUrl}/rewrite/add",
            headers=get_auth_header(),
            json={
                "domain": domain,
                "answer": target
            }
        )
        response.raise_for_status()
        globalList.add(obj)
        logger.info(f"Added to global list: {obj}")
    except Exception as e:
        logger.error(f"Failed to add DNS rewrite: {str(e)}")

def removeObject(obj, existing):
    """Remove a DNS rewrite from AdGuard Home"""
    domain, target = obj
    logger.info(f"Removing: {domain} -> {target}")

    if obj not in existing:
        logger.debug("This record doesn't exist, removing from state.")
        globalList.remove(obj)
        return

    try:
        response = requests.post(
            f"{adguardApiUrl}/rewrite/delete",
            headers=get_auth_header(),
            json={
                "domain": domain,
                "answer": target
            }
        )
        response.raise_for_status()
        globalList.remove(obj)
        logger.info(f"Removed from global list: {obj}")
    except Exception as e:
        logger.error(f"Failed to remove DNS rewrite: {str(e)}")

def handleList(newGlobalList, existing):
    """Handle changes in DNS rewrites"""
    toAdd = set([x for x in newGlobalList if x not in globalList])
    toRemove = set([x for x in globalList if x not in newGlobalList])
    toSync = set([x for x in globalList if x not in existing])

    if len(toAdd) > 0:
        logger.debug(f"Records to add: {toAdd}")
        for add in toAdd:
            addObject(add, existing)

    if len(toRemove) > 0:
        logger.debug(f"Records to remove: {toRemove}")
        for remove in toRemove:
            removeObject(remove, existing)

    if len(toSync) > 0:
        logger.debug(f"Records to sync: {toSync}")
        for sync in (toSync - toAdd - toRemove):
            addObject(sync, existing)

    printState()
    flushList()

def process_container_labels(container):
    """Process a container's labels and extract DNS records"""
    records = set()
    host_ip = container.labels.get('adguard.dns.target.override', defaultDnsRecordTarget)
    
    for key, value in container.labels.items():
        if ((key.startswith('traefik.http.routers.') or key.startswith('traefik.https.routers.'))
                and key.endswith('.rule')):
            host_directives = value.split('||')
            for directive in host_directives:
                if 'Host(' in directive:
                    directive = directive.split('Host(')[-1].rstrip(')\'" ')
                    domains = [domain.strip('` ,') for domain in directive.split(',') if domain.strip()]
                    for domain in domains:
                        records.add(tuple([domain, host_ip]))
    
    return records

def initial_sync():
    """Perform initial synchronization of all running containers"""
    global container_records
    
    logger.info("Performing initial synchronization...")
    containers = client.containers.list()
    existing = listExisting()
    
    for container in containers:
        records = process_container_labels(container)
        if records:
            container_records[container.id] = records
    
    # Combine all records from all containers
    newGlobalList = set()
    for records in container_records.values():
        newGlobalList.update(records)
    
    handleList(newGlobalList, existing)
    logger.info("Initial synchronization completed")

def handle_container_event(event):
    """Handle a Docker container event"""
    global container_records
    
    try:
        container_id = event['id']
        action = event['Action']
        logger.debug(f"Container event: {action} for {container_id}")
        
        if action == 'start':
            # Container started - add its records
            container = client.containers.get(container_id)
            records = process_container_labels(container)
            if records:
                container_records[container_id] = records
                sync_records()
        
        elif action in ['die', 'stop', 'kill']:
            # Container stopped - remove its records
            if container_id in container_records:
                del container_records[container_id]
                sync_records()
        
        elif action == 'update':
            # Container updated - refresh its records
            container = client.containers.get(container_id)
            records = process_container_labels(container)
            
            # Check if records changed
            old_records = container_records.get(container_id, set())
            if records != old_records:
                if records:
                    container_records[container_id] = records
                else:
                    container_records.pop(container_id, None)
                sync_records()
    
    except Exception as e:
        logger.error(f"Error handling container event: {e}")

def sync_records():
    """Synchronize current container records with AdGuard Home"""
    # Combine all records from all containers
    newGlobalList = set()
    for records in container_records.values():
        newGlobalList.update(records)
    
    existing = listExisting()
    handleList(newGlobalList, existing)

if __name__ == "__main__":
    if not adguardUsername or not adguardPassword:
        logger.error("AdGuard Home credentials not set. Set ADGUARD_USERNAME and ADGUARD_PASSWORD environment variables.")
        sys.exit(1)

    readState()
    initial_sync()
    
    # Listen for Docker events
    logger.info("Listening for Docker container events...")
    for event in client.events(decode=True, filters={"type": "container"}):
        handle_container_event(event)