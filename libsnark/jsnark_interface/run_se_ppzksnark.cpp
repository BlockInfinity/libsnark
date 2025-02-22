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

	// Determine the file names for the proving key and verification key.
	std::string pathArithFile = argv[1 + inputStartIndex];
	std::string arithFileName = pathArithFile.substr(pathArithFile.find_last_of("/\\") + 1);
	std::string::size_type const p(arithFileName.find_last_of('.'));
	std::string proofName = arithFileName.substr(0, p);
	std::string pkFileName = proofName + ".pk";
	std::string vkFileName = proofName + ".vk";
	
	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
		get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	if(strcmp(argv[1], "setup") == 0) {
		// Generate a key pair.
		r1cs_se_ppzksnark_keypair<libff::alt_bn128_pp> keypair = r1cs_se_ppzksnark_generator<libff::alt_bn128_pp>(cs);

		// Save the key pair to the disk.
		ofstream serializationFile1;
		serializationFile1.open(pkFileName);
		serializationFile1 << keypair.pk;
		serializationFile1.close();

		ofstream serializationFile2;
		serializationFile2.open(vkFileName);
		serializationFile2 << keypair.vk;
		serializationFile2.close();

		// Print the verification key.
		std::cout << "BEGINNING OF VERIFICATION KEY" << std::endl;
		keypair.vk.H.print();
		keypair.vk.G_alpha.print();
		keypair.vk.H_beta.print();
		keypair.vk.G_gamma.print();
		keypair.vk.H_gamma.print();
		for(std::size_t i = 0; i < keypair.vk.query.size(); ++i) {
			keypair.vk.query[i].print();
		}
		std::cout << "END OF VERIFICATION KEY" << std::endl;

		return 0;
	}

	if(strcmp(argv[1], "generate-proof") == 0) {
		// Read the key pair from the disk.
		r1cs_se_ppzksnark_keypair<libff::alt_bn128_pp> keypair = r1cs_se_ppzksnark_keypair<libff::alt_bn128_pp>();
	
		string s1;
		string line1;
		ifstream serializationFile1;
		serializationFile1.open(pkFileName);
		if(!serializationFile1.is_open()) {
			cout << "Problem occurred while opening a file." << endl;
			return -1;
		}
		serializationFile1 >> keypair.pk;
		serializationFile1.close();
		
		string s2;
		string line2;
		ifstream serializationFile2;
		serializationFile2.open(vkFileName);
		if(!serializationFile2.is_open()) {
			cout << "Problem occurred while opening a file." << endl;
			return -1;
		}
		serializationFile2 >> keypair.vk;
		serializationFile2.close();

		// Generate the proof.
		const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + cs.num_inputs());
		const r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());
		
		r1cs_se_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_se_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, primary_input, auxiliary_input);

		// Print the proof.
		std::cout << "BEGINNING OF PROOF COORDINATES" << std::endl;
		proof.A.to_affine_coordinates();
		proof.A.print_coordinates();
		proof.B.to_affine_coordinates();
		proof.B.print_coordinates();
		proof.C.to_affine_coordinates();
		proof.C.print_coordinates();
		std::cout << "END OF PROOF COORDINATES" << std::endl;

		// Print the primary input.
		std::cout << "BEGINNING OF PRIMARY INPUT" << std::endl;
		for(std::size_t i = 0; i < primary_input.size(); ++i) {
			primary_input[i].print();
		}
		std::cout << "END OF PRIMARY INPUT" << std::endl;
	
		return 0;
	}

	cout << "Invalid operation selected." << endl;
	return 2;
}

