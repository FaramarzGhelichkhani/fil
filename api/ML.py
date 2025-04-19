import numpy as np
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from fil.settings import NUMBER_OF_TRIES_CLUSTERING, INITIAL_CLUSTER, CLUSTER_STEP, MINIMUM_IP_NUMBER_PER_PAYLOAD, \
    PREFERD_PAYLOAD_PERCENT, PREFERD_OTHER_PAYLOAD_PERCENT


def clustering(data, n_cluster):
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler

    kmeans_kwargs = {
        "init": "random",
        "n_init": 10,
        "max_iter": 300,
        "random_state": 42,
    }
    numeric_features = data.select_dtypes(
        include=['int64', 'float64']).columns.values
    raw_x = data[numeric_features]

    ss = StandardScaler()
    X_scaled = ss.fit_transform(raw_x)
    kmeans = KMeans(n_clusters=n_cluster, **kmeans_kwargs)
    kmeans.fit(X_scaled)
    data.loc[:, "cluster"] = kmeans.labels_

    return data


def white_sampling(data, total_target):
    total_white = data[data["label"] == 'white'].shape[0]
    ratio = total_target / total_white
    # cluster_list = data["cluster"].unique()
    white_train_data = pd.DataFrame()

    df = data[(data["label"] == 'white')].sample(
        frac=ratio * 1.5, random_state=42)
    white_train_data = pd.concat([white_train_data, df], axis=0)

    # for cluster in cluster_list:
    #     df = data[(data["label"] == 'white') & (data["cluster"] == cluster)].sample(
    #         frac=ratio * 1.5, random_state=42)
    #     white_train_data = pd.concat([white_train_data, df], axis=0)

    return white_train_data.sample(frac=1, random_state=42)


def train_predic_cluster(data, class_name, cluster_number, threshold):
    target_data = data[(data["label"] == class_name) &
                       (data["cluster"] == cluster_number)]
    target_number = target_data.shape[0]
    print("number of {target} row: ".format(target=class_name), target_number)

    white_data = white_sampling(data, target_number)
    print("number of white row: ", len(white_data))

    train_data = pd.concat([target_data, white_data],
                           axis=0).sample(frac=1, random_state=42)

    ss = StandardScaler()
    data["asn"] = data["asn"].astype(pd.StringDtype())
    numeric_features = data.select_dtypes(
        include=['string', 'int64', 'float64']).columns.values
    raw_x = train_data[numeric_features]
    ss.fit(raw_x)
    X_scaled = ss.transform(raw_x)

    data_x = data[numeric_features]
    data_x_scaled = ss.transform(data_x)

    y = train_data.label
    train_x, test_x, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.02, random_state=42)

    rf = RandomForestClassifier(n_estimators=100, max_features='sqrt',
                                max_depth=8, criterion='gini', random_state=42, min_samples_leaf=2)

    rf.fit(train_x, y_train)

    prob = rf.predict_proba(data_x_scaled)
    prob_name1 = 'cluster_' + str(cluster_number) + \
                 '_' + list(rf.classes_)[0] + '_prob'
    prob_name2 = 'cluster_' + str(cluster_number) + \
                 '_' + list(rf.classes_)[1] + '_prob'

    df = data.copy()
    df.loc[:, prob_name1] = prob[:, 0]
    df.loc[:, prob_name2] = prob[:, 1]

    target_feature = prob_name1 if list(
        rf.classes_)[0] == class_name else prob_name2

    asns = list(df.query("label == '{}' ".format(class_name)).groupby(["asn"])["ip"].size().loc[
                    lambda x: x > 10].to_dict().keys())

    df.loc[:, "predict"] = np.where(
        (df["label"] == 'unknown') & (df[target_feature] >=
                                      threshold) & (df["asn"].isin(asns)), class_name,
        df["predict"])

    return df


NUMBER_OF_TRIES = int(NUMBER_OF_TRIES_CLUSTERING)
INITIAL_CLUSTER = int(INITIAL_CLUSTER)
CLUSTER_STEP = int(CLUSTER_STEP)
MINIMUM_IP_NUMBER_PER_PAYLOAD = int(MINIMUM_IP_NUMBER_PER_PAYLOAD)

PREFERD_PAYLOAD_PERCENT = int(PREFERD_PAYLOAD_PERCENT) / 100  # greater than equal
PREFERD_OTHER_PAYLOAD_PERCENT = int(PREFERD_OTHER_PAYLOAD_PERCENT) / 1000  # less    than equal


def find_cluster(data, cluster_number=None, tries=0):
    target_data = data.query("label != 'white' and label != 'unknown'")
    target_class = target_data.label.unique()
    count_per_target_dict = {key: val for key, val in target_data.groupby(["label"])["ip"].size().to_dict().items() if
                             val > MINIMUM_IP_NUMBER_PER_PAYLOAD}
    preferd_target_all = [key for key in count_per_target_dict.keys()]

    # clustering
    cluster = INITIAL_CLUSTER if cluster_number is None else cluster_number
    cluster_data = clustering(data, cluster)
    print("data with {} node clustered.".format(cluster))
    preferd_cluster = [key for key in
                       cluster_data.query("label != 'white' and label != 'unknown'").groupby(["cluster"])[
                           "ip"].size().to_dict().keys()]
    cluster_feature_preferd = {key: [] for key in preferd_cluster}

    tries = tries + 1
    for clus in preferd_cluster:
        count_per_clustr_dict = cluster_data.query("cluster== {cluster} ".format(cluster=clus)).groupby(["label"])[
            "ip"].size().to_dict()
        del count_per_clustr_dict["white"]
        del count_per_clustr_dict["unknown"]

        preferd_target_cluster = list(count_per_clustr_dict.keys())
        prefered_target = list(set(preferd_target_cluster)
                               & set(preferd_target_all))
        # conditions
        for f1 in prefered_target:
            f_ratio = []
            preferd_target_copy = prefered_target.copy()
            preferd_target_copy.remove(f1)
            for f2 in preferd_target_copy:
                f_ratio.append(
                    count_per_clustr_dict[f2] / count_per_target_dict[f2])
            if (count_per_clustr_dict[f1] / count_per_target_dict[f1] >= PREFERD_PAYLOAD_PERCENT and (
                    np.array(f_ratio) <= 0.1).all()) \
                    or (
                    count_per_clustr_dict[f1] / count_per_target_dict[f1] >= 0.1 and (np.array(f_ratio) == 0).all()):
                cluster_feature_preferd[clus].append(f1)

            if (count_per_clustr_dict[f1] / count_per_target_dict[f1] >= PREFERD_PAYLOAD_PERCENT and (
                    np.array(f_ratio) > 0.1).any()) and tries <= NUMBER_OF_TRIES:
                return find_cluster(data, cluster + CLUSTER_STEP, tries)

    cluster_target = []
    for val in cluster_feature_preferd.values():
        cluster_target += val
        if len(val) > 1 and tries <= NUMBER_OF_TRIES:
            return find_cluster(data, cluster + CLUSTER_STEP, tries)
    if len(cluster_target) == 0 and tries <= NUMBER_OF_TRIES:
        return find_cluster(data, cluster + CLUSTER_STEP, tries)

    if tries > NUMBER_OF_TRIES:
        cluster_feature_preferd_unoptimized = {
            key: val for key, val in cluster_feature_preferd.items() if len(val) == 1}
        print("It can not find optimized cluster number ")
        return cluster_feature_preferd_unoptimized, cluster_data

    return cluster_feature_preferd, cluster_data


def find_cluster_payload(clustered_data, payload):
    data_to_train_payload = {payload: []}
    cluster_dict = clustered_data.groupby(["cluster", "label"])["ip"]. \
        size().unstack(0, fill_value=0).to_dict()

    total_number_of_payload = clustered_data.query("label == '{}'".format(payload))["ip"].nunique()
    ip_number_of_other_payload = clustered_data.query("label != '{}' and label != 'white' ".format(payload))[
        "ip"].nunique()
    clusters = []
    for clus, val in cluster_dict.items():
        payload_number = val[payload]
        del val[payload]
        del val["white"]
        other_payload_number = sum(cluster_dict[clus].values())
        if (
                payload_number > MINIMUM_IP_NUMBER_PER_PAYLOAD and payload_number / total_number_of_payload >= PREFERD_PAYLOAD_PERCENT and \
                other_payload_number / ip_number_of_other_payload <= PREFERD_OTHER_PAYLOAD_PERCENT) \
                or (payload_number > MINIMUM_IP_NUMBER_PER_PAYLOAD and \
                    other_payload_number < 10):

            preferd_data = clustered_data.query(" cluster == {cluster} and label == '{pay}' ". \
                                                format(cluster=clus, pay=payload)).copy()

            preferd_data.drop('cluster', axis=1, inplace=True)
            data_to_train_payload[payload].append(preferd_data)
            clusters.append(clus)

        elif payload_number / total_number_of_payload >= PREFERD_PAYLOAD_PERCENT and \
                other_payload_number / ip_number_of_other_payload > PREFERD_OTHER_PAYLOAD_PERCENT:
            return False, data_to_train_payload, clusters
    # print("{} data found at cluster  with {} nodes.".format(payload ,clus+1))
    return True, data_to_train_payload, clusters


def find_cluster_v2(data):
    preferd_data_to_train = {}
    running = True
    tries = 0
    labeld_data = data.query(" label != 'unknown' ").copy()
    payloads = [key for key, val in labeld_data.query("label != 'white'").groupby(["label"])["ip"].
        size().to_dict().items() if
                val > MINIMUM_IP_NUMBER_PER_PAYLOAD]
    print("clustering for these payloads started:\n", payloads)

    while running and NUMBER_OF_TRIES > tries:
        step = CLUSTER_STEP * tries
        clustered_data = clustering(labeld_data, INITIAL_CLUSTER + step)
        print("data clustered with {} nodes. ".format(INITIAL_CLUSTER + step))

        for payload in payloads:
            flag, data_to_train_payload, clusters = find_cluster_payload(clustered_data, payload)
            if flag and len(data_to_train_payload) > 0:
                preferd_data_to_train = {**preferd_data_to_train, **data_to_train_payload}
                deleted_data = labeld_data.loc[
                    (clustered_data["cluster"].isin(clusters)) & (clustered_data["label"] == payload)]
                labeld_data.drop(deleted_data.index, axis=0, inplace=True)
                payloads.remove(payload)
            if flag is False and len(data_to_train_payload) > 0:
                preferd_data_to_train = {**preferd_data_to_train, **data_to_train_payload}

        tries += 1
        if len(payloads) == 0:
            running = False

    return preferd_data_to_train


def train_predict_cluster_v2(all_data, data_for_train, payload, probability_threshold):
    target_number = data_for_train.shape[0]
    print("number of {target} row: ".format(target=payload), target_number)

    # all_data_clustering = clustering(all_data, 10)
    white_data = white_sampling(all_data, target_number)
    print("number of white row: ", len(white_data))

    train_data = pd.concat([data_for_train, white_data],
                           axis=0).sample(frac=1, random_state=42)

    ss = StandardScaler()
    train_data["asn"] = train_data["asn"].astype(pd.StringDtype())
    all_data["asn"] = all_data["asn"].astype(pd.StringDtype())
    numeric_features = data_for_train.select_dtypes(
        include=['string', 'int64', 'float64']).columns.values
    raw_x = train_data[numeric_features]
    ss.fit(raw_x)
    X_scaled = ss.transform(raw_x)
    y = train_data.label

    rf = RandomForestClassifier(n_estimators=100, max_features='sqrt',
                                max_depth=8, criterion='gini', random_state=42, min_samples_leaf=2)

    rf.fit(X_scaled, y)

    data_x = all_data[numeric_features]
    data_x_scaled = ss.transform(data_x)

    prob = rf.predict_proba(data_x_scaled)
    prob_name1 = "{}".format(payload) + '_' + list(rf.classes_)[0] + '_prob'
    prob_name2 = "{}".format(payload) + '_' + list(rf.classes_)[1] + '_prob'

    df = all_data.copy()
    df.loc[:, prob_name1] = prob[:, 0]
    df.loc[:, prob_name2] = prob[:, 1]

    target_feature = prob_name1 if list(
        rf.classes_)[0] == payload else prob_name2
    asns = list(df.query("label == '{}' ".format(payload)).groupby(["asn"])["ip"].size().loc[
                    lambda x: x > 10].to_dict().keys())

    df.loc[:, "predict"] = np.where(
        (df["label"] == 'unknown') & (df[target_feature] >=
                                      probability_threshold) & (df["asn"].isin(asns)), payload,
        df["predict"])

    df.drop(prob_name1, axis=1, inplace=True)
    df.drop(prob_name2, axis=1, inplace=True)

    return df


def train_predict(data, threshold_proba=0.99):
    data_traf = data.loc[(data.total_traffic >= 1e+09)].copy()
    print("Information about data set with more than 1GB traffic : ")
    print(data_traf.groupby(["label"])["ip"].size())
    cluster_feature, data_cluster = find_cluster(data_traf)

    for cluster, features in cluster_feature.items():
        for feature in features:
            print("##################")
            print("{} in cluster {} start to train:".format(feature, cluster))
            data_cluster = train_predic_cluster(
                data_cluster, feature, cluster, threshold=threshold_proba)

    return data_cluster


def train_predict_v2(data, threshold_proba=0.99):
    data_traf = data.loc[(data.total_traffic >= 1e+09)].copy()
    print("Information about data set with more than 1GB traffic : ")
    print(data_traf.groupby(["label"])["ip"].size())

    data_to_train = find_cluster_v2(data=data_traf)

    for payload, dataframe_list in data_to_train.items():
        for df in dataframe_list:
            print("##################")
            print("{} start to train:".format(payload))

            data = train_predict_cluster_v2(data, df, payload, threshold_proba)

    return data


def train_predict_v3(data, threshold_proba=0.97):
    data_traf = data.loc[(data.total_traffic >= 1e+09)].copy()
    print("Information about data set with more than 1GB traffic : ")
    print(data_traf.groupby(["label"])["ip"].size())

    payloads = [key for key, val in data_traf.query("label != 'white' and label != 'unknown'").groupby(["label"])["ip"]. \
        size().to_dict().items() if
                val > MINIMUM_IP_NUMBER_PER_PAYLOAD]
    print(payloads)
    for payload in payloads:
        df = data_traf.query("label == '{}' ".format(payload)).copy()
        print("##################")
        print("{} start to train:".format(payload))

        data = train_predict_cluster_v2(data, df, payload, threshold_proba)

    return data
