/*
   ************************************************
	Author: Ali Raza
	Date: 01/09/2019.
    Crypto Scheme:
	Boradcast Encryption
   ************************************************

   Implemented on Type-3 pairing

   Compile with modules as specified below

   For MR_PAIRING_CP curve
   cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_MNT curve
   mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
	
   For MR_PAIRING_BN curve
   bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
	Test Program.
    */

#include <iostream>
#include <ctime>
#include <time.h>
//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************
#include <vector>
#include "pairing_3.h"
// initialise pairing-friendly curve
PFC pfc(AES_SECURITY);
// lenght of hash
#define HASH_LEN 32
/*
This hash function takes a string as input and outputs
a hash of Big data type. 
*/
Big H1(string ID)
{ 
	Big return_value;
	GT g;
	char myChar  = {0};
	myChar=ID[0];
	return pfc.hash_to_aes_key(myChar);
}

/****************/
// Global vectors used in the function combinationofID
vector<Big> people;
vector<Big> combination;
vector<vector<Big>> combinations;

// This function finds the distinct combination of k elements at a time.
void combinationofID(int offset, int k) {
	if (k == 0) {
		 combinations.push_back(combination);
		 return;
	}
	for (int i = offset; i <= people.size() - k; ++i) {
		 combination.push_back(people[i]);
		 combinationofID(i + 1, k - 1);
		 combination.pop_back();
	}
}
// get pairing-friendly group order
Big order=pfc.order(); 

/*This function finds the sum of products of distinct combinations of k
elements out of total n elements of given array arr[].
*/
Big sumOfProduct(string arr[],int k,int n){

	for (int i = 0; i < n; ++i) { people.push_back(H1(arr[i])); }
	combinationofID(0, k);
	Big sum =0;
	for(int x=0;x<combinations.size();x++)
	{
		Big product =1;
		for(int y=0;y<combinations[x].size();y++)
		{
			product =modmult(product,combinations[x][y],order) ;
		}
		sum += product;
	}
	return sum;
}
#include <string>
using namespace std;
int main()

{  // get handle on mip (Miracl Instance Pointer)
	miracl* mip=get_mip();   

	//////////////////////////
	//Setup
	/////////////////////////
	cout<<"************************Setup***************************************"<<endl;

	//////////////////////////////////////////////////////////////////////////////////////////////
	//  Public parameters are :
	//  G1, G2, GT, w, v, h, h1[m-1]=h^(gama), h1[m-2]=h^(gama^(2)),..., h1[0]=h^(gama^(m)), order.
	//////////////////////////////////////////////////////////////////////////////////////////////
	
	//Public Parameter h.
	G2 h;
	//Public Parameter v.
	GT v;
	//Public Parameter w.
	G1 w;

	/************************************************************************************/
	// Variables for Private Parameter gama and k.
	Big gamma,k;
	//variables for Generator g, C1 and private key skid.
	G1 g,C1,skid;
	//variables for C2.
	G2 C2;
	//variables for key K.
	GT K;
	/************************************************************************************/
	/************************************************************************************/
	//we will use the following variables to store different values later in our code.
	//Elements of Big data type.
	Big mul_id,pid;
	//Group G2 element.
	G2 sum_h;
	//Group GT elements.
	GT K0,K1;
	/***********************************************************************************/
	/*
	The time_t datatype is a data type in the ISO C library defined for storing system time values.
	Such values are returned from the standard time() library function.
	*/
	time_t seed;         
	 //Time seed value.                 
	time(&seed); 
	//creat random number of long type from the seed value.
    irand((long)seed);        
	// Pointers to strings, initialize to Null.
	string* ID = NULL; 
	string* S = NULL;
	string* ID2 = NULL; 
	// Size needed for array (Maximum number of users).
	int m;  

	cout<<"Enter total number of users"<<endl;
	// Read the total number of users
	cin >>m;
	// Allocate m strings and save pointer in ID.
	ID = new string[m]; 
	// Allocate m strings and save pointer in S. We will store receivers in array S.
	S = new string[m];
	// Allocate m strings and save pointer in ID2.
	ID2 = new string[m]; 
	// s the total number of receivers.
	int s;
	// variable of int data type.
	int q,q1=0,q2=1;
	
	//get the total number of receivers.
	cout<<"Enter total number of Receivers"<<endl;
	cin >>s;

	if(s>m){
		cout<<"Receivers cannot exceed maximum number of Users "<<endl;
		//system pause call
			system("pause");
		return 0;
	}
	/* Here is a trailing character '\n' remaining from last cin>>, so getline take this '\n' character
	and gets terminated, to avoid this ignore the content of buffer before getline.
	*/
	cin.ignore();
	
	// Pointer to G1, initialize to Null.
	G1* skID = NULL;
	// Allocate m strings and save pointer in skID. We will use this array to store the private keys. 
	skID = new G1[m];
	 //randomly generate gama
	pfc.random(gamma);
	// randomly generate g
	pfc.random(g);
	// randomly generate h
	pfc.random(h);
	// Pointer to G1, initialize to Null.
	G2* h1 = NULL;
	// Allocate m strings and save pointer in h1.
	h1=new G2[m];
	
	int t=0,tt=1;
	Big gammataotal=1;
	int yy=m;

	/*Here we find h^(gama^m), h^(gama^m-1), h^(gama^m-2) ... h^(gama^1).
	*/
	while(t<m){
		gammataotal=1;
		while(tt<=yy){
			gammataotal=modmult(gamma,gammataotal,order);
			tt=tt+1;
		}
		h1[t]=pfc.mult(h,modmult(gammataotal,1,order));
		yy=yy-1;
		t=t+1;
		tt=1;
	}
	/* w=g*gama instead of g^gama. We changed multiplicative group operations into additive group operations,
	becasue there is no function to calculate G1^Big. Here G1 and Big are elements of data type G1 and Big
	respectively.
	*/
	w=pfc.mult(g,gamma);
	//precompute w
	pfc.precomp_for_mult(w);
	// e(h,g)
	v=pfc.pairing(h,g);
	// Master secret key is (g,gama)
	
	
	//////////////////////////
	//Encryption
	/////////////////////////
		cout<<"************************Encryption***************************************"<<endl;
	
		string receiver_id;
		int b1=0;
		while (q2<=s)
		{
			cout<<"Enter Receiver "<<q1+1<<endl;
			getline(cin, receiver_id);
			// get the ID of receiver.
					S[q1]=receiver_id;
			q1=q1+1;
			q2=q2+1;
		}
	
	//Generate random k.
	pfc.random(k);

	/*mip is the Miracl Instance Pointer. mip->IOBASE=16 simply changes the base to 16(Hexadecimal).
	We use the hexadecimal numbers to make coding for microprocessor. But it converts that to binary
	for computation. After the computation the result will be in hexadecimal format by inverse conversion.
	*/
	mip->IOBASE=16;

	/* C1=w*(-K) instead of C1=w^(-k). We changed multiplicative group operations into 
	additive group operations, becasue there is no function to calculate G1^Big.
	Here G1 and Big are elements of data type G1 and Big respectively.
	*/
	C1=pfc.mult(w,-(k));
	int n=s;
	Big* aggregate = NULL;
	aggregate = new Big[s];
	int p=1;
	int pp=0;
	while(p<=s){
	/*Find the sum of product of distinct combinations. Taking p out of total n array S`s elements.
	and store the output in array aggregate.
	*/
	aggregate[pp]= sumOfProduct(S, p, n);
	//clear the vector people
	people.clear();
	//clear the vector combination
	combination.clear();
	//clear the vector combinations
	combinations.clear();
	pp=pp+1;
	p=p+1;
	}
	/* 
	We use modmult() to avoid too much big numbers, as a result of multiplication. 
	*/
	C2=pfc.mult(h1[m-s],k);
	int o=0, TT=m-s+1;
	while(o<s-1){
		C2=C2+pfc.mult(pfc.mult(h1[TT],k),aggregate[o]);
		o=o+1;
		TT=TT+1;
	}
	C2=C2+pfc.mult(h,modmult(k,aggregate[s-1],order));
	// K=v^k
	K=pfc.power(v,k);
	/*mip is the Miracl Instance Pointer. mip->IOBASE=16 simply changes the base to 16(Hexadecimal).
	We use the hexadecimal numbers to make coding for microprocessor. But it converts that to binary
	for computation. After the computation the result will be in hexadecimal format by inverse conversion.
	*/
	mip->IOBASE=16;
	//Print the Hash of Master Secret Key.
	cout << "Hash of Key K = " <<  pfc.hash_to_aes_key(K) << endl; 
	//////////////////////////
	//Extract
	/////////////////////////
	cout<<"************************Extraction***************************************"<<endl;
	int b=0; 
	while (b<m)
	{   cout<<"enter ID for User "<<b+1<<endl;      
	// Input the ID string for each User.
	getline(cin, ID[b]); 
		b=b+1;
	}
	cout<< "************************************************************************ "<<endl;

	/* compute secret key skID for each user. We compute g*(inverse(gama+H1(ID[s1]),order))
	   instead of g^(inverse(gama+H1(ID),order)). We changed multiplicative group operations
		into additive group operations, becasue there is no function to calculate G1^Big.
		Here G1 and Big are elements of data type G1 and Big respectively.
		*/
		int s0=m,s1=0;
		while(s0!=0){
			skID[s1]=pfc.mult(g,inverse((gamma+H1(ID[s1])),order));
			//Print the skID for each user.
			cout << "Secret  Key skID of "<<ID[s1]<<" = "<< skID[s1].g << endl;
		s0=s0-1;
		s1=s1+1;
		}
	////////////////////////////
	//Decryption
	///////////////////////////
	cout<<"************************Decryption***************************************"<<endl;
	int e=0;
	cout<< "****************List of Receivers*************************************** "<<endl;
	while(e<s){
		
		cout<<e+1<<" = "<<S[e]<<endl;
		e=e+1;
	}
	cout<< "************************************************************************ "<<endl;

	// Varibales we will use later
	int Rec_user,save_input;
	int i=0,i2=0;
	int l=0,l1=0;
	char input_repeat;
	string sample_receiver_id;
	bool Found;
		int b2;
	repeat:
		Found=false;
		b2=0;
			cout<<"Enter the sample Recipient User "<<endl;
			getline(cin, sample_receiver_id);
	        //put the respective user from the set of user in to the set of receivers.
			while(b2<m){
				if(ID[b2]==sample_receiver_id){
					Rec_user=b2;
					Found=true;
					goto out1;
				}
				b2=b2+1;
			}
	out1:
			if(!Found){cout<<"User not found"<<endl;
			//system pause call
			system("pause");
			return 0 ;
			}
	//save the sample Recipient.
	save_input=Rec_user;

	i=0,i2=0;
	 l=0,l1=0;
	while(i<n){
		if(ID[Rec_user]==S[i2]){
			Rec_user=i2;
	while (l<n)
	{//store elements of S in ID2 except the sample recipient ID if the sample recipient is present in S.
		if(l!=Rec_user){
		ID2[l1]=S[l];
	l1=l1+1;}
		l=l+1;	
	}
	goto LABEL1;
		}
		else
		{
			i2=i2+1;
			i=i+1;
		}
	}
	 
	LABEL1:
	int n1 =s-1;
	Big* aggregate2 = NULL;
	aggregate2 = new Big[n1];
	int p1=1;
	int pp1=0;
	while(p1<=n1){
	/*find the sum of product of distinct combination of p elements out of total n elements of array ID2.
	and store the output in array aggregate.
	*/
	aggregate2[pp1]= sumOfProduct(ID2, p1, n1);
	//clear the vector people
	people.clear();
	//clear the vector combination
	combination.clear();
	//clear the vector combinations
	combinations.clear();
	pp1=pp1+1;
	p1=p1+1;
	}
	int z1=m-s+2,z=0;
	if(s>2){
	sum_h=h1[z1]; 
	while(z<s-3){
		sum_h=sum_h+pfc.mult(h1[z1+1],aggregate2[z]);
	z=z+1;
	z1=z1+1;
	}
	sum_h=sum_h+pfc.mult(h,aggregate2[s-3]);
	}
	else
	{
		sum_h=h;
	}
	mul_id=1;
	int i5=s,i6=0;
	while(i5!=0){
		if(i6!=Rec_user){
			mul_id=modmult(H1(S[i6]),mul_id,order);
	}
		i5=i5-1;
		i6=i6+1;
	}
	// Rec_user=save_input;
	Rec_user=save_input;
	//K1=pfc.pairing((sum_h,C1)*(pfc.pairing(C2,skID[Rec_user]));
	K1=pfc.pairing(sum_h,C1)*(pfc.pairing(C2,skID[Rec_user]));
	// k= k1^(1/mul_id)
	K=pfc.power(K1,(inverse(mul_id,order)));
	/*mip is the Miracl Instance Pointer. mip->IOBASE=16 simply changes the base to 16(Hexadecimal).
	We use the hexadecimal numbers to make coding for microprocessor. But it converts that to binary
	for computation. After the computation the result will be in hexadecimal format by inverse conversion.
	*/
	mip->IOBASE=16;
	//Print the hash of Master Key.
	cout << "Hash of Key K = " << pfc.hash_to_aes_key(K) << endl;
	cout<<"Do you want to Dercypt for another user Y/N"<<endl;
	cin>>input_repeat;
	if(input_repeat=='Y'){
    /* Here is a trailing character '\n' remaining from last cin>>, so getline take this '\n' character
	and gets terminated, to avoid this ignore the content of buffer before getline.
	*/
	cin.ignore();
		//goto repeat label
	goto  repeat;
	}
	//system pause call
	system("pause");
	return 0;
    }
