/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS SEppzkSNARK for
 a given R1CS example.

 See run_r1cs_se_ppzksnark.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_SE_PPZKSNARK_TCC_
#define RUN_R1CS_SE_PPZKSNARK_TCC_

#include <iostream>
#include <fstream>
#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark.hpp>

#include <iostream>
#include <chrono>
#include <ctime>

namespace libsnark {

	void printElapsedTime(std::string message, std::chrono::system_clock::time_point startTime) {
		std::chrono::system_clock::time_point endTime = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsedSeconds = endTime - startTime;
		std::cout << "Time measurement : " << message << ": " << elapsedSeconds.count() << std::endl;
	}

/**
 * The code below provides an example of all stages of running a R1CS SEppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the SEppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the SEppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the SEppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_se_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example,
						   const bool test_serialization, std::chrono::system_clock::time_point startTime,
						   bool restoreKeypair)
{
    libff::enter_block("Call to run_r1cs_se_ppzksnark");

    libff::print_header("R1CS SEppzkSNARK Generator");
	printElapsedTime("before key pair generation", startTime);
	// Create an empty key pair (takes virtually no time).
	r1cs_se_ppzksnark_keypair<ppT> keypair = r1cs_se_ppzksnark_keypair<ppT>();
	if(!restoreKeypair) {
		r1cs_se_ppzksnark_keypair<ppT> newKeypair = r1cs_se_ppzksnark_generator<ppT>(example.constraint_system);
		// Fill the key pair with actual keys.
		keypair.pk = newKeypair.pk;
		keypair.vk = newKeypair.vk;

		// Save the key pair to the disk.
		ofstream serializationFile1;
		serializationFile1.open("pk");
		serializationFile1 << keypair.pk;
		serializationFile1.close();

		ofstream serializationFile2;
		serializationFile2.open("vk");
		serializationFile2 << keypair.vk;
		serializationFile2.close();
	} else {
		string s1;
		string line1;
		ifstream serializationFile1;
		serializationFile1.open("pk");
		if(!serializationFile1.is_open()) {
			cout << "Problem occurred while opening a file." << endl;
			return -1;
		}
		serializationFile1 >> keypair.pk;
		serializationFile1.close();
		
		string s2;
		string line2;
		ifstream serializationFile2;
		serializationFile2.open("vk");
		if(!serializationFile2.is_open()) {
			cout << "Problem occurred while opening a file." << endl;
			return -1;
		}
		serializationFile2 >> keypair.vk;
		serializationFile2.close();
	}
	
    libff::print_header("R1CS SEppzkSNARK Prover");
    r1cs_se_ppzksnark_proof<ppT> proof = r1cs_se_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
	printElapsedTime("after proof generation", startTime);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    std::cout << "PRINTING VERIFICATION KEY" << std::endl;
	keypair.vk.H.print();
	keypair.vk.G_alpha.print();
	keypair.vk.H_beta.print();
	keypair.vk.G_gamma.print();
	keypair.vk.H_gamma.print();
    for(std::size_t i = 0; i < keypair.vk.query.size(); ++i) {
      keypair.vk.query[i].print();
    }

    std::cout << "PRINTING PROOF COORDINATES" << std::endl;
    proof.A.to_affine_coordinates();
    proof.A.print_coordinates();
    proof.B.to_affine_coordinates();
    proof.B.print_coordinates();
    proof.C.to_affine_coordinates();
    proof.C.print_coordinates();

    std::cout << "PRINTING PRIMARY INPUT" << std::endl;
    for(std::size_t i = 0; i < example.primary_input.size(); ++i) {
      example.primary_input[i].print();
    }
 
    std::cout << "PRINTING TEMPLATE VARIABLE AGAIN" << std::endl;
    std::cout << __PRETTY_FUNCTION__ << std::endl;

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_se_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("R1CS SEppzkSNARK Verifier");
	printElapsedTime("before verification", startTime);
    const bool ans = r1cs_se_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
	printElapsedTime("after verification", startTime);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

	/*
    libff::print_header("R1CS SEppzkSNARK Online Verifier");
    const bool ans2 = r1cs_se_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);
	*/
	
    libff::leave_block("Call to run_r1cs_se_ppzksnark");

    return ans;
}

} // libsnark

#endif // RUN_R1CS_SE_PPZKSNARK_TCC_
