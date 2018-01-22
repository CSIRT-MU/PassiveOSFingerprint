from configparser import ConfigParser
from getpass import getpass
from neo4j.v1 import GraphDatabase, basic_auth


def configure(path_to_config):
    """
    Parse values from configuration file, which are needed to access database.
    :param path_to_config:  path to configuration file.
    :return: driver for database.
    """
    config = ConfigParser()
    config.read(path_to_config)
    neo4j_name = config.get("Neo4j", "Name")
    neo4j_password = config.get("Neo4j", "Password")
    neo4j_connector = config.get("Neo4j", "Bolt")
    if not neo4j_password:
        print('Enter your neo4j password')
        neo4j_password = getpass()
    return GraphDatabase.driver(neo4j_connector, auth=basic_auth(neo4j_name, neo4j_password))


def prepare_DB(driver):
    """
    Initialization point of the program.
    :param driver: driver for neo4j
    :return: None
    """
    session = driver.session()
    tx = session.begin_transaction()
    tx.run("CREATE CONSTRAINT ON (host:HOST) ASSERT host.ip_address IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (os:OS) ASSERT os.os_name IS UNIQUE")
    tx.commit()
    tx.close()


def update_DB(file_path, driver):
    """
    Create required cypher query for uploading data to database.
    :param file_path: path to json file with data which will be uploaded.
    add - only add data.
    del - delete HAS_OS_ACTUAL relationship and replace it with HAS_OS_HISTORY relationship.
    upt - update combine add and delete to reach update scenario.
    skip - currently not supported since id does nothing with database data.
    :param driver: driver for neo4j
    :return: None.
    """

    add_query = f'CALL apoc.load.json("file://{file_path}") YIELD value as data ' \
                'UNWIND data.add AS add ' \
                'MERGE (host:HOST {ip_address: add.ip}) ' \
                'MERGE (os:OS {os_name: add.os}) ' \
                'CREATE (host)-[:HAS_OS_ACTUAL {time: data.time}]->(os)'

    upt_del_query = f'CALL apoc.load.json("file://{file_path}") YIELD value as data ' \
                'UNWIND data.upt AS upt ' \
                'MATCH (host:HOST {ip_address:upt.ip})-[r:HAS_OS_ACTUAL]->(os:OS) ' \
                'CREATE (host)-[r2:HAS_OS_HISTORY]->(os) ' \
                'SET r2.time = r.time ' \
                'WITH r ' \
                'DELETE r'

    upt_add_query = f'CALL apoc.load.json("file://{file_path}") YIELD value as data ' \
                'UNWIND data.upt AS upt ' \
                'MERGE (host:HOST {ip_address: upt.ip}) ' \
                'MERGE (os:OS {os_name: upt.os}) ' \
                'CREATE (host)-[:HAS_OS_ACTUAL {time: data.time}]->(os)'

    del_query = f'CALL apoc.load.json("file://{file_path}") YIELD value as data ' \
                'UNWIND data.del AS del ' \
                'MATCH (host:HOST {ip_address:del.ip})-[r:HAS_OS_ACTUAL]->(os:OS) ' \
                'CREATE (host)-[r2:HAS_OS_HISTORY]->(os) ' \
                'SET r2.time = r.time ' \
                'WITH r ' \
                'DELETE r'

    session = driver.session()
    tx = session.begin_transaction()
    tx.run(del_query)
    tx.run(upt_del_query)
    tx.run(upt_add_query)
    tx.run(add_query)
    tx.commit()
    tx.close()
