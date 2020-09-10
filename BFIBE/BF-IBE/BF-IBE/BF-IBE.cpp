/*
   *********************************
	Author: Ali Raza
	Date: 01/08/2019.
    Crypto Scheme:Boneh-Franklin IBE
   **********************************
   Compile with modules as specified below

	For MR_PAIRING_SSP curves
	BF-IBE.cpp ssp_pair.cpp ecn.cpp zzn2.cpp zzn.cpp big.cpp miracl.lib
  
	For MR_PAIRING_SS2 curves
     BF-IBE.cpp ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.lib
    
	or of course

    BF-IBE.cpp ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.a -o bgw


   Test program 
*/

#include <iostream>
#include <ctime>

#include <stdlib.h>



//********* CHOOSE JUST ONE OF THESE **********
#define MR_PAIRING_SS2    // AES-80 or AES-128 security GF(2^m) curve
//#define AES_SECURITY 80   // OR
#define AES_SECURITY 128

//#define MR_PAIRING_SSP    // AES-80 or AES-128 security GF(p) curve
//#define AES_SECURITY 80   // OR
//#define AES_SECURITY 128
//*********************************************

#include "pairing_1.h"

// initialise pairing-friendly curve
PFC pfc(AES_SECURITY);  

/* H2 maps a GT element in to hash of (0,1)*/
Big H2(GT g){
	
	Big HASH;
	HASH=pfc.hash_to_aes_key(g);
	return HASH;}


int main()
{   
	
	 // get handle on mip (Miracl Instance Pointer)
    miracl* mip=get_mip();  
	// get pairing-friendly group order
	Big order=pfc.order();    
	//Initilization of public parameters
	//parameters of big type
	Big ID,s,M,r,V;      
	  // Group G1 type elements
	G1 P,Ppub,Qid,did,U; 
	/*The time_t datatype is a data type in the ISO C library defined for storing system time values. Such values
	are returned from the standard time() library function
	we use get a seed for our random number.
	*/
	time_t seed;   
	// initialise (insecure!) random numbers
	time(&seed);      
	  //  creat random number of long type from the seed value.
    irand((long)seed);     
	//Character id
	char id; 
	 // Groupt GT elements.
	GT gID,gid2,g2;          
	
	cout << "************************ Boneh-Franklin IBE ******************* " << endl;


	
// setup
	cout << "Starting Setup" << endl;
	
	//generate random value of s
	pfc.random(s);	
	//generate random value of P
	pfc.random(P);
	//precompute P
	pfc.precomp_for_mult(P); 
	 // ppub=P*s
	Ppub=pfc.mult(P,s);     
	//precompute ppub
	pfc.precomp_for_mult(Ppub);
	
	cout << "Setup Completed" << endl;
	cout << "**************************************************************" << endl;
	//Extract
	cout << "Starting Extraction" << endl;
	
	// Qid=H1(ID). Here ID= Alice and H1 (we use pfc.hash_and_map() as H1) maps a character string to G1 element.
	pfc.hash_and_map(Qid,"Alice");

	// did=Qid*s . Here ID= Alice
	did=pfc.mult(Qid,s);
	cout << "Extraction Completed" << endl;

	cout << "**************************************************************" << endl;
	//Encrypt
	cout << "Starting Encryption" << endl;

/*	mip is the Miracl Instance Pointer. mip->IOBASE=256 simply changes the base to 256.
    We take input in a base 256 to componsate all the real world letters and special characters.
	Which are easy to be represented in base 256 system of numbers.
*/
	mip->IOBASE=256;
	// to be encrypted to Alice, convert it from char to Big data type.
	M=(char *)"test message"; 

	//print "Message to be encrypted"
	cout << "Message to be Encrypted= " << M << endl;  
	/*
	mip is the Miracl Instance Pointer. mip->IOBASE=16 simply changes the base to 16(Hexadecimal).
	We use the hexadecimal numbers to make coding for microprocessor. But it coonverts that to binary
	for computation. After the computation the result will be in hexadecimal format by inverse conversion.
	*/
	mip->IOBASE=16;

	 

	 // generate random r
	pfc.random(r); 

	 // U= r*P
	U=pfc.mult(P,r); 

	// Qid=H1(ID) . Here ID= Alice
	pfc.hash_and_map(Qid,"Alice");
	//gID= e(QID,Ppub).
	gID=pfc.pairing(Qid,Ppub); 

	 // gid2= (gID)^r
	gid2=pfc.power(gID,r);
	
	// V= M (XOR) H2((gID)^r)
	V=lxor(M,H2(gid2));
	cout << "Encryption Completed" << endl;

	cout << "**************************************************************" << endl;
	//Decryption:

	cout << "Starting Decryption" << endl;

	// M=V(xor)H2(e(did,U)).
	M=lxor(V,H2(pfc.pairing(did,U)));

	/*
	mip is the Miracl Instance Pointer. mip->IOBASE=16 simply changes the base to 16(Hexadecimal).
	We will convert the result back to base 256 from base 16, because if we output the result in base 16 it will not be same as
	the input as the input was in base 256. So we need to change back the base of number system to 256. So tha we can get
	same output and input display.
	*/
	mip->IOBASE=256;
	cout << "Decrypted Message= " << M << endl;
	cout << "Decrytpion Completed" << endl;
	cout << "**************************************************************" << endl;
	system("pause");
	 return 0;
}
