import logging
from pythonjsonlogger import jsonlogger

import os
import time
from kubernetes import client, config
import base64
import hvac

logging.getLogger().setLevel(logging.INFO)
format_str = '%(levelname)%(message)'
formatter = jsonlogger.JsonFormatter(format_str)
logHandler = logging.StreamHandler()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)

def initialize(vaultClient, shares, threshold):

    result = vaultClient.sys.initialize(secret_shares=shares,secret_threshold=threshold)
    logger.debug(result)
    rootToken = result['root_token']
    keys = result['keys']
    return keys, rootToken

def getClusterInfo(vaultClient):

    logger.debug('Getting cluster info ...')
    status = vaultClient.sys.read_health_status(method='GET')
    logger.debug(status)
    clusterId = status['cluster_id']
    clusterName = status['cluster_name']
    return clusterId, clusterName

def unseal(vaultClient, keys):

    unseal_response = vaultClient.sys.submit_unseal_keys(keys)
    logger.debug(unseal_response)

def getKeysFromSecret(k8sApi, k8sNamespace, k8sSecretPrefix):

    logger.debug("Getting unseal keys from kubernetes namespace {0}".format(k8sNamespace))
    try:
        secret = k8sApi.read_namespaced_secret(name=f'{k8sSecretPrefix}unseal',namespace=k8sNamespace)
    except Exception as e:
        logger.fatal(e)
        exit(1)
    logger.debug(secret.data)
    logger.info('Unseal secret {0}unseal retrieved from kubernetes'.format(k8sSecretPrefix))
    keys = []
    for k,v in secret.data.items():
        keys.append(base64.b64decode(v).decode('utf-8'))
    logger.debug(keys)
    return keys

def createSecret(k8sApi, k8sNamespace, secretName, secretData, clusterId, clusterName):

    secret = {'data' : secretData,
                'metadata' : {
                    'annotations': {
                        'vault-cluster-name' : clusterName,
                        'vault-cluster-id' : clusterId
                    },
                    'name' : secretName
                }
            }
    logger.debug(secret)
    try:
        api_response = k8sApi.create_namespaced_secret(namespace=k8sNamespace,body=secret)
    except Exception as e:
        logger.fatal(e)
        exit(1)
    logger.debug(api_response)


def main():

    logger.info("Starting vault-init ...")

    vaultAddr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
    logger.debug("VAULT_ADDR is {0}".format(vaultAddr))

    checkInterval = os.environ.get('CHECK_INTERVAL', '10')
    logger.debug("CHECK_INTERVAL is {0}".format(checkInterval))

    try:
        checkInterval = int(checkInterval)
    except ValueError as e:
        logger.fatal("CHECK_INTERNAL value needs to be an integer")
        raise ValueError('CHECK_INTERNAL value needs to be an integer')
    
    k8sNamespace = os.environ.get('K8S_NAMESPACE', 'default')
    logger.debug("K8S_NAMESPACE is {0}".format(k8sNamespace))

    k8sSecretPrefix = os.environ.get('K8S_SECRET_PREFIX', 'vault-')
    logger.debug('K8S_SECRET_PREFIX is {0}'.format(k8sSecretPrefix))

    # SERVICE_HOST_ENV_NAME = "KUBERNETES_SERVICE_HOST"
    # SERVICE_PORT_ENV_NAME = "KUBERNETES_SERVICE_PORT"
    # SERVICE_TOKEN_FILENAME = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    # SERVICE_CERT_FILENAME = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    config.load_incluster_config()

    v1 = client.CoreV1Api()
    logger.debug('Checking list capabilities of secrets in namespace {0}'.format(k8sNamespace))
    try:
        api_response = v1.list_namespaced_secret(namespace=k8sNamespace)
    except client.rest.ApiException as e:
        if e.status == 403:
            logger.fatal('No permission to list secrets in the {0} namespace'.format(k8sNamespace))
        logger.fatal(e.reason)
        logger.fatal(e.body)
        exit(403)
    except Exception as e:
        logger.fatal(e)
        exit(1)
    else:
        logger.debug('List capabilities available for secrets')

    keys = clusterId = clusterName = vaultInit = None
    vaultClient = hvac.Client(url=vaultAddr)
    if not vaultClient.sys.is_initialized():
        logger.warning("Vault at {0} is not initialized".format(vaultAddr))
        logger.debug("Initializing ...")
        keys, rootToken = initialize(vaultClient,5,3)
        logger.info("Vault at {0} is initialized".format(vaultAddr))
        vaultInit = True
    else:
        logger.info("Vault at {0} is initialized".format(vaultAddr))
        keys = getKeysFromSecret(v1, k8sNamespace, k8sSecretPrefix)
  
    if vaultClient.sys.is_sealed():
        logger.warning("Vault at {0} is sealed".format(vaultAddr))
        logger.debug("Unsealing ...")
        unseal(vaultClient, keys)
        logger.info("Vault at {0} is unsealed".format(vaultAddr))

    logger.debug("Getting cluster info ...")
    clusterId, clusterName = getClusterInfo(vaultClient)
    logger.info("Vault cluster name is {0} with id {1}".format(clusterName, clusterId))

    # Write unseal keys and root token
    if vaultInit == True:

        logger.debug("Unseal keys returned by vault init, pushing to kubernetes ...")
        secretName = f'{k8sSecretPrefix}unseal'
        keysdict = {}
        i = 1
        for k in keys:
            keysdict[f'key{i}'] = base64.b64encode(bytes(k, 'utf-8')).decode('utf-8')
            i=i+1
        logger.debug(keysdict)
        createSecret(v1, k8sNamespace, secretName, keysdict, clusterId, clusterName)
        logger.info("Unseal keys stored in kubernetes secret {0}".format(secretName))

        logger.debug("Pushing root token secret to kubernetes ...")
        secretName = f'{k8sSecretPrefix}root'
        token = {'token' : base64.b64encode(bytes(rootToken, 'utf-8')).decode('utf-8')}
        createSecret(v1, k8sNamespace, secretName, token, clusterId, clusterName)
        logger.info("root token stored in kubernetes secret {0}".format(secretName))

    while True:

        if vaultClient.sys.is_sealed():
            logger.warning("Vault at {0} is sealed".format(vaultAddr))
            logger.debug("Unsealing ...")
            unseal(vaultClient, keys)
            logger.info("Vault at {0} is unsealed".format(vaultAddr))
        else:
            logger.info("Vault at {0} is still unsealed".format(vaultAddr))

        logger.debug("Sleeping for {0} seconds".format(checkInterval))
        time.sleep(checkInterval)

if __name__ == '__main__':
    main()
