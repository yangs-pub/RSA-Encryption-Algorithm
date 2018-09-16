import base64
from tkinter import *
import random
import math
def encipherment(text,e,n):                 #原文本加密函数
    

    Ascii=[]
    for i in range(len(text)):
        Ascii.append(ord(text[i]))

    miwen=b''
    for x in range(len(Ascii)):
        m=(pow(int(Ascii[x]),e)%n).to_bytes(4, 'little')
        miwen+=m
    Miwen=base64.b64encode(miwen).decode('ascii')


    return Miwen
def decipherment(Miwen,d,n):                #密文解密函数
    Yuanwen=''  

    Miwen=base64.b64decode(Miwen.encode('ascii'))
    for i in range(0,len(Miwen),4):
        Yuanwen=Yuanwen+chr(pow(int.from_bytes(Miwen[i:i+4],'little'),d,n))
        
    return Yuanwen    

       
def miyue_create():                         #密钥生成函数
    def xn_mod_p2(x, n, p):                         #检验是否为质数的拉宾米勒算法
      res = 1                                       #可以较快的检验一个数
      n_bin = bin(int(n))[2:]                       #是否为质数
      for i in range(0, len(n_bin)):                #但牺牲了准确性，
        res = res**2 % p                            #我的质数生成函数0.024%（1/4096）
        if n_bin[i] == '1':                         #的错误率
          res = res * x % p
      return res
    def miller_rabin_witness(a, p):
      if p == 1:
        return False
      if p == 2:
        return True
      #p-1 = u*2^t 求解 u, t
      n = p - 1
      t = int(math.floor(math.log(n, 2)))
      u = 1
      while t > 0:
        u = n / 2**t
        if n % 2**t == 0 and u % 2 == 1:
          break
        t = t - 1
      b1 = b2 = xn_mod_p2(a, u, p)
      for i in range(1, t + 1):
        b2 = b1**2 % p
        if b2 == 1 and b1 != 1 and b1 != (p - 1):
          return False
        b1 = b2
      if b1 != 1:
        return False
      return True
    def prime_test_miller_rabin(p, k):
      while k > 0:
        a = random.randint(1, p - 1)
        if not miller_rabin_witness(a, p):
          return False
        k = k - 1
      return True
    def Pri(up):
        n=False
        k=6
        while n==False:
            p=random.randrange(1001,up)
            n=prime_test_miller_rabin(p, k)
        return p
            
            
    p=Pri(10000)
    q=Pri(10000)
    while p==q:
        q=Pri(10000)
    n=p*q
    fn=(p-1)*(q-1)
    e=Pri(fn)
    d=int((fn+1)/e)
    while (d*e-1)%fn!=0:
        d=d+1
    return n, e, d



class App(Frame):                                   #界面函数
    def __init__(self):
        Frame.__init__(self)
        self.master.geometry('540x360')
        self.master.title('RSA加密算法')
        self.maininterface()
        self.miyue()

    def maininterface(self):
        top=self.winfo_toplevel()
        self.grid(sticky=NSEW)
        top.grid_columnconfigure(0,weight=1)
        self.rowconfigure(0,weight=1)
        self.rowconfigure(1,weight=1)
        self.columnconfigure(0,weight=1)
        self.columnconfigure(1,weight=2)
        self.columnconfigure(2,weight=1)
        self.columnconfigure(3,weight=2)
        self.gongyue = Entry(self)                          #显示公钥
        self.gongyue.grid(row=0, column=2, sticky=NSEW)
        self.lb_gongyue = Label(self, text='公钥')
        self.lb_gongyue.grid(row=0, column=1, sticky=NSEW)
        self.siyue = Entry(self)                          #显示私钥
        self.siyue.grid(row=1, column=2, sticky=NSEW)
        self.lb_siyue = Label(self, text='私钥')
        self.lb_siyue.grid(row=1, column=1, sticky=NSEW)
        self.btn_gen = Button(self, text='生成密钥', width=10, command=self.miyue)
        self.btn_gen.grid(row=0, column=1, rowspan=2, sticky=NSEW)
        self.text=Text(self)
        self.text.grid(row=2,column=1,columnspan=2,sticky=NSEW)
        self.btn_enc=Button(self,text='加密文本',width=18,command=self.jiamiwenben)
        self.btn_enc.grid(row=1,column=0,sticky='NSW')
        self.btn_enc=Button(self,text='解密文本',width=18,command=self.jiemiwenben)
        self.btn_enc.grid(row=0,column=0,sticky='NSE')
    def miyue(self):
        n,e,d=miyue_create()
        self.gongyue.delete('0',END)
        self.gongyue.insert('0','%d,%d'%(e,n))
        self.siyue.delete('0',END)
        self.siyue.insert('0','%d,%d'%(d,n))
    

    
       
        
    def jiamiwenben(self):
        text=self.text.get('1.0',END)
        GONGYUE = self.gongyue.get().strip().split(',')
        self.text.replace('1.0',END,encipherment(text,int(GONGYUE[0]),int(GONGYUE[1])))
    
    def jiemiwenben(self):
        text=self.text.get('1.0',END)
        SIYUE = self.siyue.get().strip().split(',')
        self.text.replace('1.0',END,decipherment(text,int(SIYUE[0]),int(SIYUE[1])))


if __name__=="__main__":
    app =  App()
    app.mainloop()
    
