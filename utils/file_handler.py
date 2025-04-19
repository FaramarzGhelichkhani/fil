import logging
import pickle
import redis
from typing import List
from fil.settings import REDIS_DOMAIN_DB, REDIS_HOST, REDIS_IP_HOURLY_DB, REDIS_PORT, REDIS_DNS_DB
from utils.ipmeta.classes import IpMeta
from utils.ipmeta.main import check_ipmeta_completion
from multiprocessing import Pool
from functools import partial

logger = logging.getLogger()


def get_memory_usage():
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=1)
    return redis_client.info('memory')


def save_domainmetas_in_redis(objects, db, expire):
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=db)
    pipe = redis_client.pipeline()
    for object in objects:
        pipe.setex(name=str(object[0]), value=pickle.dumps(object[1]), time=expire)
    result = pipe.execute()
    return all(result)


def save_ipmetas_in_redis(objects: List[IpMeta], db, expire):
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=db)
    pipe = redis_client.pipeline()
    for object in objects:
        pipe.setex(name=str(object.ip), value=pickle.dumps(object), time=expire)
    result = pipe.execute()
    return all(result)


def save_ipmetas_in_redis_single(obj, db, expire):
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=db)
    redis_client.setex(name=str(obj.ip), value=pickle.dumps(obj), time=expire)
    return True


def save_ipmeta_in_redis_multiprocess(objects: List[IpMeta], db, expire, processor_number=10):
    func = partial(save_ipmetas_in_redis_single, db=db, expire=expire)
    with Pool(processor_number) as pool:
        results = pool.map(func, objects)
    return all(results)

def save_object_in_redis(object, key, db, expire):
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=db)
    pipe = redis_client.pipeline()
    pipe.setex(name=key, value=pickle.dumps(object), time=expire)
    result = pipe.execute()
    return all(result)


def load_saved_object_from_redis(key, db):
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=db)
    pipe = redis_client.pipeline()
    pipe.get(key)
    result = pipe.execute()
    return pickle.loads(result[0])


def get_keys_from_redis(db,redis_host=None):
    host = redis_host  if redis_host != None else REDIS_HOST
    redis_client = redis.Redis(host=host, port=REDIS_PORT, db=db)
    keys = redis_client.keys()
    return keys


def get_dbsize_from_redis(db):
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=db)
    dbsize = redis_client.dbsize()
    return dbsize


def load_objects_from_redis(keys, db, redis_host=None):
    host = redis_host  if redis_host != None else REDIS_HOST
    redis_client = redis.Redis(host=host, port=REDIS_PORT, db=db)
    result = redis_client.mget(keys=keys)
    checked_result = []
    for ipmeta_pickle in result:
        if ipmeta_pickle:
            checked_result.append(ipmeta_pickle)
    result.clear()
    return checked_result

def load_complete_ipobjects_from_redis(keys,redis_host=None):
    db = REDIS_IP_HOURLY_DB
    host = redis_host  if redis_host != None else REDIS_HOST
    redis_client = redis.Redis(host=host, port=REDIS_PORT, db=db)
    pipe = redis_client.pipeline()
    for key in keys:
        pipe.get(key)
    result = pipe.execute()
    return list(filter(lambda x: check_ipmeta_completion(ipmeta=pickle.loads(x)) == True , result))


def load_domain_from_redis(domain):
    dns_redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DNS_DB)
    keys = dns_redis_client.keys(pattern=domain + '>*')
    pipe = dns_redis_client.pipeline()
    for key in keys:
        pipe.get(key)
    dns_result = pipe.execute()
    domain_redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DOMAIN_DB)
    keys = domain_redis_client.keys(pattern=domain + '>*')
    pipe = domain_redis_client.pipeline()
    for key in keys:
        pipe.get(key)
    domain_result = pipe.execute()
    return dns_result, domain_result


def save_objects_in_file(objects: List[object], filename: str):
    with open(f"{filename}.obj", 'ab') as writer:
        pickle.dump(objects, writer)


def load_objects_from_file(filename: str):
    with open(filename, 'rb') as reader:
        r = reader.read(1024 * 1024 * 1024)
    obj = pickle.loads(r)
    objects = []
    for i in obj:
        objects.append(i)
    objects = list(set(objects))
    reader.close()
    return objects
