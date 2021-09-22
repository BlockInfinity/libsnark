/*
 * run_ppzksnark.cpp
 *
 *      Author: Ahmed Kosba, Christoph Michelbach
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/examples/run_r1cs_se_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark.hpp>

#include <iostream>
#include <chrono>
#include <ctime>

int main(int argc, char **argv) {
	auto startTime = std::chrono::system_clock::now();
	
	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	int inputStartIndex = 1;

	// argv[1] specifies the operation. Valid values are:
	// - setup
	// - generate-proof
	
	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);

	if(strcmp(argv[1], "setup") == 0) {
		// Generate a key pair.
		r1cs_se_ppzksnark_keypair<libff::alt_bn128_pp> keypair = r1cs_se_ppzksnark_generator<libff::alt_bn128_pp>(cs);

		// Save the key pair to the disk.
		ofstream serializationFile1;
		serializationFile1.open("pk");
		serializationFile1 << keypair.pk;
		serializationFile1.close();

		ofstream serializationFile2;
		serializationFile2.open("vk");
		serializationFile2 << keypair.vk;
		serializationFile2.close();

		// Print the verification key.
		std::cout << "PRINTING VERIFICATION KEY" << std::endl;
		keypair.vk.H.print();
		keypair.vk.G_alpha.print();
		keypair.vk.H_beta.print();
		keypair.vk.G_gamma.print();
		keypair.vk.H_gamma.print();
		for(std::size_t i = 0; i < keypair.vk.query.size(); ++i) {
			keypair.vk.query[i].print();
		}

		return 0;
	}

	if(strcmp(argv[1], "generate-proof") == 0) {
		// Read the key pair from the disk.
		r1cs_se_ppzksnark_keypair<libff::alt_bn128_pp> keypair = r1cs_se_ppzksnark_keypair<libff::alt_bn128_pp>();
	
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

		// Generate the proof.
		const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
		const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + cs.num_inputs());
		const r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());
		
		r1cs_se_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_se_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, primary_input, auxiliary_input);

		// Print the proof.
		std::cout << "PRINTING PROOF COORDINATES" << std::endl;
		proof.A.to_affine_coordinates();
		proof.A.print_coordinates();
		proof.B.to_affine_coordinates();
		proof.B.print_coordinates();
		proof.C.to_affine_coordinates();
		proof.C.print_coordinates();

		return 0;
	}

	cout << "Invalid operation selected." << endl;
	return 2;
}

