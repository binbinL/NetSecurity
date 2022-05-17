import pickle
import DataShuffle
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import lightgbm as lgb
from sklearn.model_selection import StratifiedKFold, KFold
import numpy as np
from numpy import *
from scipy.optimize import linear_sum_assignment as linear_assignment
from lightgbm import LGBMClassifier
import numpy as np
from xgboost import XGBClassifier
import xgboost as xgb
import numpy as np
import warnings


warnings.filterwarnings("ignore")  #忽略告警

def cluster_acc(y_true, y_pred):
    y_true = np.array(y_true).astype(np.int64)
    assert y_pred.size == y_true.size
    D = max(y_pred.max(), y_true.max()) + 1
    w = np.zeros((D, D), dtype=np.int64)
    for i in range(y_pred.size):
        w[y_pred[i], y_true[i]] += 1
    ind = linear_assignment(w.max() - w)
    sum = 0
    for i in range(len(ind[0])):
        j = ind[0][i]
        k = ind[1][i]
        sum += w[j, k]
    return sum * 1.0 / y_pred.size

def to_dict(rate):
    dictrate = {}
    for i in range(len(rate)):
        dictrate[label_dict[i]] = rate[i]

    return dictrate

col_name=["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
          "logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations",
          "num_shells","num_access_files","num_outbound_cmds","is_hot_login","is_guest_login","count","srv_count",
          "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
          "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
          "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]
label_map={'back.': 0, 'buffer_overflow.': 1, 'ftp_write.': 2, 'guess_passwd.': 3, 'imap.': 4, 'ipsweep.': 5, 'land.': 6, 'loadmodule.': 7, 'multihop.': 8, 'neptune.': 9, 'nmap.': 10, 'normal.': 11, 'perl.': 12, 'phf.': 13,
           'pod.': 14, 'portsweep.': 15, 'rootkit.': 16, 'satan.': 17, 'smurf.': 18, 'spy.': 19, 'teardrop.': 20, 'warezclient.': 21, 'warezmaster.': 22}



col_transform=['protocol_type','service','flag','label']
col_continuous=['src_bytes','dst_bytes','wrong_fragment','urgent','hot','num_failed_logins','num_compromised',
                'num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds','count',
                'srv_count']

label_dict = {0: 'back.', 1: 'buffer_overflow.', 2: 'ftp_write.', 3: 'guess_passwd.', 4: 'imap.', 5: 'ipsweep.', 6: 'land.', 7: 'loadmodule.', 8: 'multihop.', 9: 'neptune.',
              10: 'nmap.', 11: 'normal.', 12: 'perl.', 13: 'phf.', 14: 'pod.', 15: 'portsweep.', 16: 'rootkit.', 17: 'satan.', 18: 'smurf.', 19: 'spy.', 20: 'teardrop.', 21: 'warezclient.', 22: 'warezmaster.'}

X_train,y_train,X_test,y_test,class_num=DataShuffle.getTrandTest()
# for c_name in col_continuous:
#     datas[c_name]=(datas[c_name]-min(datas[c_name]))/max(datas[c_name])
#
# lbl = LabelEncoder()
# for col in col_transform:                                                    #使用LabelEncoder将中文，英文单词等转为数字替代
#     lbl.fit(datas[col])
#     datas[col] = lbl.transform(datas[col])
    # tsdatas[col] = lbl.transform(tsdatas[col])

#
# class_num=max(datas['label'])
#
# for i in col_name:
#     isnan=datas[i].isnull().any()
#     if isnan:
#         datas[i]=datas[i].fillna(0)
#         # tsdatas[i]=tsdatas[i].fillna(0)
#
# test_label=[]
# for i in range(len(datas['label'])):
#     if i%10==0:
#         test_label.append(datas['label'][i])
#         datas['label'][i]=-1
#
# train=datas[datas['label']!=-1]
# test = datas[datas['label']==-1]
#
# X_train = train.drop('label',1)
# y_train = train['label']
# X_test = test.drop('label',1)
# y_test=test_label
#
# jsondic = {}
#
# for i in label_map.keys():
#     jsondic[label_map[i]]=i

# params = {'num_leaves': 60,
#           'min_data_in_leaf': 30,
#           'objective': 'multiclass',
#           'num_class': class_num+1,
#           'max_depth': -1,
#           'learning_rate': 0.03,
#           "min_sum_hessian_in_leaf": 6,
#           "boosting": "gbdt",
#           "feature_fraction": 0.9,
#           "bagging_freq": 1,
#           "bagging_fraction": 0.8,
#           "bagging_seed": 11,
#           "lambda_l1": 0.1,
#           "verbosity": -1,
#           "nthread": 15,
#           'metric': 'multi_logloss',
#           "random_state": 2019,
#           'device': 'gpu'
#           }
#
#
# folds = KFold(n_splits=5, shuffle=True, random_state=2019)
# prob_oof = np.zeros((X_train.shape[0], class_num))
# test_pred_prob = np.zeros((test.shape[0], class_num))
#
# ## train and predict
# feature_importance_df = pd.DataFrame()
# for fold_, (trn_idx, val_idx) in enumerate(folds.split(train)):
#     print("fold {}".format(fold_ + 1))
#     trx=X_train.iloc[trn_idx]
#     trv=X_train.iloc[val_idx]
#     trx_y=y_train.iloc[trn_idx]
#     trv_y=y_train.iloc[val_idx]
#     trn_data = lgb.Dataset(trx, label=trx_y)
#     val_data = lgb.Dataset(trv, label=trv_y)
#
#     clf = lgb.train(params,
#                     trn_data,
#                     valid_sets=[trn_data, val_data],
#                     verbose_eval=20,
#                     early_stopping_rounds=60)
#     trv=X_train.iloc[val_idx]
#     prob_oof[val_idx] = clf.predict(trv, num_iteration=clf.best_iteration)
#
#
#     fold_importance_df = pd.DataFrame()
#     fold_importance_df["Feature"] = col_name
#     fold_importance_df["importance"] = clf.feature_importance()
#     fold_importance_df["fold"] = fold_ + 1
#     feature_importance_df = pd.concat([feature_importance_df, fold_importance_df], axis=0)
#
#     test_pred_prob += clf.predict(test[col_name], num_iteration=clf.best_iteration) / folds.n_splits
# result = np.argmax(test_pred_prob, axis=1)
#
# print(cluster_acc(test_label,result))
#
# clf_multiclass = LGBMClassifier()
# clf_multiclass.fit(X_train,y_train)
# val_pred = clf_multiclass.predict(X_test)
#
# print(cluster_acc(y_test,val_pred))

# """XGBoost"""
clf_multiclass = XGBClassifier()
clf_multiclass = XGBClassifier(
                        learning_rate=0.1,
                        n_estimators=900,         # 树的个数--1000棵树建立xgboost
                        max_depth=6,               # 树的深度
                        min_child_weight = 1,      # 叶子节点最小权重
                        gamma=0.,                  # 惩罚项中叶子结点个数前的参数
                        subsample=0.8,             # 随机选择80%样本建立决策树
                        colsample_btree=0.8,       # 随机选择80%特征建立决策树
                        objective='multi:softmax', # 指定损失函数
                        scale_pos_weight=1,        # 解决样本个数不平衡的问题
                        random_state=27)

clf_multiclass.fit(X_train,y_train)
val_pred = clf_multiclass.predict(X_test)
print(cluster_acc(y_test,val_pred))
# pickle.dump(clf_multiclass, open("sum.dat", "wb"))  save

# loaded_model = pickle.load(open("sum.dat", "rb"))
# val_pred = loaded_model.predict(X_test)
# strc ="0	tcp	private	SH	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	1	1	1	1	0	0	1	0	0	255	1	0	1	1	0	1	1	0	0"
# stra = "0,tcp,http,SF,256,1169,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,4,4,0.00,0.00,0.00,0.00,1.00,0.00,0.00,4,139,1.00,0.00,0.25,0.04,0.00,0.00,0.00,0.00"
# stra = input("输入：")
# loaded_model = pickle.load(open("shuffle1.dat", "rb"))
# val_pred = loaded_model.predict(DataShuffle.convert(stra))    #结果
# probabilitys =loaded_model.predict_proba(DataShuffle.convert(stra))
# print(cluster_acc(y_test,val_pred))
# print(DataShuffle.to_json(probabilitys))
# print(DataShuffle.getTopN(7,probabilitys))
#
# rates = loaded_model.predict_proba(X_test)  #概率
#
# print(to_dict(rate=rates[1000]))
# for i in range(len(test_label)):
#     if test_label[i]!=val_pred[i]:
#         print(i,test_label[i],val_pred[i])
#         print(rates[i])
# rates= clf_multiclass.predict_proba(X_test)
# print(cluster_acc(y_test,val_pred))

# params = {
#     'booster': 'gbtree',
#     'objective': 'multi:softmax',  # 多分类的问题
#     'num_class': class_num+1,               # 类别数，与 multisoftmax 并用
#     'gamma': 0.1,                  # 用于控制是否后剪枝的参数,越大越保守，一般0.1、0.2这样子。
#     'max_depth': 12,               # 构建树的深度，越大越容易过拟合
#     'lambda': 2,                   # 控制模型复杂度的权重值的L2正则化项参数，参数越大，模型越不容易过拟合。
#     'subsample': 0.7,              # 随机采样训练样本
#     'colsample_bytree': 0.7,       # 生成树时进行的列采样
#     'min_child_weight': 3,
#     'silent': 1,                   # 设置成1则没有运行信息输出，最好是设置为0.
#     'eta': 0.007,                  # 如同学习率
#     'seed': 1000,
#     'nthread': 4,                  # cpu 线程数
# }
#
# dtrain = xgb.DMatrix(X_train, y_train)
# num_rounds = 20
# model = xgb.train(params, dtrain, num_rounds)
#
# dtest = xgb.DMatrix(X_test)
# pred = model.predict(dtest)
# rate = model.predict_proba(dtest)
# print(type(pred))
# print(rate)