def toLowerCase(text):
    n=len(text)
    result = ""
    for i in range(n):
        if 65<=ord(text[i])<=91:
            result += chr(ord(text[i])+32)
        else:
            result += text[i]
    return result
def removeSpace(text):
    n=len(text)
    temp=""
    for i in range(n):
        if text[i]!=' ':
            temp+=text[i]
    return temp

def generateKeyTable(key,keyT):
    n=len(key)
    keyT.clear()
    for i in range(5):
        keyT.append([0]*5)
    hashMap=[0]*26
    for i in range(n):
        if key[i]!='j':
            hashMap[ord(key[i])-97]=2
    hashMap[ord('j')-97]=1
    i=0
    j=0
    for k in range(n):
        if hashMap[ord(key[k])-97]==2:
            hashMap[ord(key[k])-97]-=1
            keyT[i][j]=key[k]
            j+=1
            if j==5:
                i+=1
                j=0
    for k in range(26):
        if hashMap[k]==0:
            keyT[i][j]=chr(k+97)
            j+=1
            if j==5:
                i+=1
                j=0

def search(keyT,a,b,arr):
    if a=='j':
        a='i'
    if b=='j':
        b='i'
    for i in range(5):
        for j in range(5):
            if keyT[i][j]==a:
                arr[0]=i
                arr[1]=j
            elif keyT[i][j]==b:
                arr[2]=i
                arr[3]=j
def prepare(string):
    result = ""
    i = 0
    while i < len(string):
        result += string[i]
        if i + 1 < len(string):
            if string[i] == string[i+1]:
                result += 'x'
            else:
                result += string[i+1]
                i += 1
        i += 1
    if len(result) % 2 != 0:
        result += 'z'
    return result

def encrypt(string,keyT):
    n=len(string)
    arr= [0]*4
    result=list(string)
    for i in range(0,n,2):
        search(keyT,result[i],result[i+1],arr)
        if arr[0]==arr[2]:
            result[i]=keyT[arr[0]][(arr[1]+1)%5]
            result[i+1]=keyT[arr[0]][(arr[3]+1)%5]
        elif arr[1]==arr[3]:
            result[i] = keyT[(arr[0] + 1) % 5][arr[1]]
            result[i + 1] = keyT[(arr[2] + 1) % 5][arr[1]]
        else:
            result[i] = keyT[arr[0]][arr[3]]
            result[i + 1] = keyT[arr[2]][arr[1]]
    return ''.join(result)
def encryptByPlayfairCipher(string, key):
    keyT = []
    key = toLowerCase(removeSpace(key))
    string = toLowerCase(removeSpace(string))
    string = prepare(string)
    generateKeyTable(key, keyT)
    print("Prepared text:", string)
    generateKeyTable(key, keyT)
    print("Key table:")
    for row in keyT:
        print(row)
    return encrypt(string, keyT)

key = input("enter key: ")
string = input("enter plain text: ")
print("Key text:", key)
print("Plain text:", string)
cipher = encryptByPlayfairCipher(string, key)
print("Cipher text:", cipher)

