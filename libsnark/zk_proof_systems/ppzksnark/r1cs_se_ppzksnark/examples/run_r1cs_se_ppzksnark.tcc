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

namespace libsnark {

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
                        const bool test_serialization)
{
    libff::enter_block("Call to run_r1cs_se_ppzksnark");

    libff::print_header("R1CS SEppzkSNARK Generator");
    r1cs_se_ppzksnark_keypair<ppT> keypair = r1cs_se_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_se_ppzksnark_processed_verification_key<ppT> pvk = r1cs_se_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_se_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_se_ppzksnark_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<r1cs_se_ppzksnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    libff::print_header("R1CS SEppzkSNARK Prover");
    r1cs_se_ppzksnark_proof<ppT> proof = r1cs_se_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
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
    /*	ofstream myfile4H;
	myfile4H.open ("verification_key_H");
	myfile4H << keypair.vk.H;
	myfile4H.close();
    
	ofstream myfile4G_alpha;
	myfile4G_alpha.open ("verification_key_G_alpha");
	myfile4G_alpha << keypair.vk.G_alpha;
	myfile4G_alpha.close();
    
    
	ofstream myfile4H_beta;
	myfile4H_beta.open ("verification_key_H_beta");
	myfile4H_beta << keypair.vk.H_beta;
	myfile4H_beta.close();
    
    
	ofstream myfile4G_gamma;
	myfile4G_gamma.open ("verification_key_G_gamma");
	myfile4G_gamma << keypair.vk.G_gamma;
	myfile4G_gamma.close();
    
    
	ofstream myfile4H_gamma;
	myfile4H_gamma.open ("verification_key_H_gamma");
	myfile4H_gamma << keypair.vk.H_gamma;
	myfile4H_gamma.close();
    
    for(std::size_t i = 0; i < keypair.vk.query.size(); ++i) {
      ofstream myfile4query;
      myfile4query.open ("verification_key_query_" + std::to_string(i));
      myfile4query << keypair.vk.query[i];
      myfile4query.close();
    }*/

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
      /*
      ofstream myfile2;
      myfile2.open ("primary_input_" + std::to_string(i));
      myfile2 << example.primary_input[i];
      myfile2.close();
      */
    }
 
    //std::cout << "PRINTING PRIMARY INPUT" << std::endl;
    //std::cout << example.primary_input << std::endl;


    std::cout << "PRINTING TEMPLATE VARIABLE AGAIN" << std::endl;
    std::cout << __PRETTY_FUNCTION__ << std::endl;

    /*
    ofstream myfile3;
	myfile3.open ("primary_input");
	myfile3 << example.primary_input;
	myfile3.close();

	ofstream myfile4;
	myfile4.open ("proof");
	myfile4 << proof;
	myfile4.close();

	ofstream myfile6;
	myfile6.open ("proof_point_coordinate_a");
	myfile6 << proof.A;
	myfile6.close();

	ofstream myfile7;
	myfile7.open ("proof_point_coordinate_b");
	myfile7 << proof.B;
	myfile7.close();

	ofstream myfile8;
	myfile8.open ("proof_point_coordinate_c");
	myfile8 << proof.C;
	myfile8.close();
    */

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_se_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("R1CS SEppzkSNARK Verifier");
    const bool ans = r1cs_se_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS SEppzkSNARK Online Verifier");
    const bool ans2 = r1cs_se_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);

    libff::leave_block("Call to run_r1cs_se_ppzksnark");

    return ans;
}

} // libsnark

#endif // RUN_R1CS_SE_PPZKSNARK_TCC_
