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

	int operation = -1;
	int inputStartIndex = 1;

	// argv[1] specifies the operation. Valid values are:
	// - setup
	// - generate-proof
	// - verify-proof
	
	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
		get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
												   full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
													   full_assignment.begin() + cs.num_inputs(), full_assignment.end());

	printElapsedTime("defined input", startTime);
	// only print the circuit output values if both flags MONTGOMERY and BINARY outputs are off (see CMakeLists file)
	// In the default case, these flags should be ON for faster performance.

	//assert(cs.is_valid());

	// removed cs.is_valid() check due to a suspected (off by 1) issue in a newly added check in their method.
	// A follow-up will be added.
	if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is not satisifed by the value assignment - Terminating." << endl;
		return -1;
	}
	printElapsedTime("checked constraint system satisfaction", startTime);

	r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
	printElapsedTime("created example", startTime);
	const bool test_serialization = false;
	bool successBit = false;

	successBit = libsnark::run_r1cs_se_ppzksnark<libff::default_ec_pp>(example, test_serialization, startTime, true);
	printElapsedTime("ran example function", startTime);

	if(!successBit){
		cout << "Problem occurred while running the ppzksnark algorithms .. " << endl;
		return -1;
	}	
	return 0;
}

