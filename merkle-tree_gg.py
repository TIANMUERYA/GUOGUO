import hashlib
import copy

def hash_leaf(data,hash_function = 'sha256'):#merkle树叶节点
    hash_function = getattr(hashlib, hash_function)
    data = b'\x00'+data.encode('utf-8')
    return hash_function(data).hexdigest()
    
def hash_node(data,hash_function = 'sha256'):#merkle树中间节点
    hash_function = getattr(hashlib, hash_function)
    data = b'\x01'+data.encode('utf-8')
    return hash_function(data).hexdigest()

def Create_Merkle_Tree(lst, hash_function = 'sha256'):
    lst_hash = []
    for i in lst:
        lst_hash.append(hash_leaf(i))
    merkle_tree = [copy.deepcopy(lst_hash)]
    assert len(lst_hash)>2, "no tracnsactions to be hashed"
    n = 0 #merkle树高度
    while len(lst_hash) >1:
        n += 1
        if len(lst_hash)%2 == 0:#偶数个叶节点
            v = []
            while len(lst_hash) >1 :
                a = lst_hash.pop(0)
                b = lst_hash.pop(0)
                v.append(hash_node(a+b, hash_function))
            merkle_tree.append(v[:])
            lst_hash = v
        else:#奇数个叶节点
            v = []
            last_leaf = lst_hash.pop(-1)         
            while len(lst_hash) >1 :
                a = lst_hash.pop(0)
                b = lst_hash.pop(0)
                v.append(hash_node(a+b, hash_function))
            v.append(last_leaf)
            merkle_tree.append(v[:])
            lst_hash = v
    #print(merkle_tree)
    return lst_hash, n+1 ,merkle_tree

def Generate_Proof(merkle_tree,h,n,message,hash_function = 'sha256'):
    proof_list =[]
    hash_value = hash_leaf(message,hash_function)
    proof_list.append(hash_value) #叶子结点的hash值
    i = 1
    while i<h:
        L = len(merkle_tree[i-1])
        if L%2 == 1 and L-1 == n:
            break
        elif n%2 == 1:
            hash_value = hash_node(merkle_tree[i-1][n-1]+hash_value,hash_function)
            proof_list.append(hash_value)
        elif n%2 == 0:
            hash_value = hash_node(hash_value+merkle_tree[i-1][n+1],hash_function)
            proof_list.append(hash_value)
        n = n//2
        i += 1
    return proof_list

def Verify_Proof(merkle_tree,h,n,message,proof,hash_function = 'sha256'):
    count = 1
    #print(len(merkle_tree))
    print("验证的叶子节点为：",message)
    print("该叶子节点的路径证明为：",proof)
    for i in range(len(proof)):
        if merkle_tree[i][n] == proof[i]:
            break
            #print('true')
            #print(i)
        else:
            count = 0
        if n==1:
            break
        else: n = n//2
    if count == 1:
        print("该路径证明合法")
    else:
        print("该路径证明非法")

            


lst = ['a','b','c','d','e','f','g','h','i']
#lst = []
#for i in range(100000):
#    lst.append(str(i))
tree_root,h,merkle_tree = Create_Merkle_Tree(lst)
print("根结点hash值：",tree_root)
print("Merkle树的高度：",h)
proof_list = Generate_Proof(merkle_tree,h,0,'a')
print("路径证明为：")
for j in range(len(proof_list)):
    print(proof_list[j])
Verify_Proof(merkle_tree,h,0,'a',proof_list)
Verify_Proof(merkle_tree,h,3,'d',proof_list)





