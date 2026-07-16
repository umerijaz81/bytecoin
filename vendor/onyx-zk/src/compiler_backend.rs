//! Deterministic Halo2 lowering boundary for canonical `ONXIR` v1.
//!
//! This first backend profile deliberately accepts only one call-free scalar function over Pasta
//! fields and booleans. Unsupported integer/composite/control-flow instructions fail closed. The
//! circuit shape retains the decoded program in `without_witnesses`, so key generation commits to
//! opcode/selector placement rather than to runtime witnesses.

use ff::Field;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error, Instance, Selector, SingleVerifier,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use sha2::{Digest, Sha256};

const IR_DOMAIN: &[u8] = b"ONXIR\x01";
const DESCRIPTOR_DOMAIN: &[u8] = b"bytecoin.onyx.compiler-halo2-descriptor.v1";
const MAX_IR_BYTES: usize = 64 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 1024;
const MAX_INSTRUCTIONS: usize = 1_000_000;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScalarType {
    Bool,
    Field,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Visibility {
    Public,
    Private,
}

#[derive(Clone, Debug)]
struct Parameter {
    visibility: Visibility,
    name: String,
    kind: ScalarType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opcode {
    Parameter,
    Constant,
    Not,
    And,
    Or,
    Equal,
    NotEqual,
    Add,
    Subtract,
    Multiply,
    Assert,
    Return,
}

#[derive(Clone, Debug)]
struct Instruction {
    opcode: Opcode,
    result: Option<usize>,
    kind: ScalarType,
    operands: Vec<usize>,
    immediate: Option<u64>,
}

#[derive(Clone, Debug)]
struct Function {
    parameters: Vec<Parameter>,
    instructions: Vec<Instruction>,
}

#[derive(Clone, Debug)]
pub struct CompilerProgram {
    profile_digest: [u8; 32],
    ir_digest: [u8; 32],
    function: Function,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompilerBackendError {
    InvalidEncoding,
    NonCanonicalInteger,
    LimitExceeded,
    UnsupportedType,
    UnsupportedInstruction,
    InvalidProgram,
    InvalidWitness,
    KeyGeneration,
    ProofCreation,
    ProofVerification,
    ProofTooLarge,
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], CompilerBackendError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(CompilerBackendError::LimitExceeded)?;
        if end > self.data.len() {
            return Err(CompilerBackendError::InvalidEncoding);
        }
        let result = &self.data[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn byte(&mut self) -> Result<u8, CompilerBackendError> {
        Ok(self.take(1)?[0])
    }

    fn uleb(&mut self) -> Result<u64, CompilerBackendError> {
        let start = self.offset;
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            if shift >= 64 && byte & 0x7f != 0 {
                return Err(CompilerBackendError::LimitExceeded);
            }
            value |= u64::from(byte & 0x7f)
                .checked_shl(shift)
                .ok_or(CompilerBackendError::LimitExceeded)?;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if self.offset - start > 10 {
                return Err(CompilerBackendError::LimitExceeded);
            }
        }
        let mut canonical = Vec::new();
        let mut remaining = value;
        loop {
            let byte = (remaining & 0x7f) as u8;
            remaining >>= 7;
            canonical.push(byte | if remaining == 0 { 0 } else { 0x80 });
            if remaining == 0 {
                break;
            }
        }
        if canonical.as_slice() != &self.data[start..self.offset] {
            return Err(CompilerBackendError::NonCanonicalInteger);
        }
        Ok(value)
    }

    fn text(&mut self, maximum: usize) -> Result<String, CompilerBackendError> {
        let length =
            usize::try_from(self.uleb()?).map_err(|_| CompilerBackendError::LimitExceeded)?;
        if length > maximum {
            return Err(CompilerBackendError::LimitExceeded);
        }
        let text = std::str::from_utf8(self.take(length)?)
            .map_err(|_| CompilerBackendError::InvalidEncoding)?;
        if !text.is_ascii() {
            return Err(CompilerBackendError::UnsupportedType);
        }
        Ok(text.to_owned())
    }
}

fn scalar_type(text: &str) -> Result<ScalarType, CompilerBackendError> {
    match text {
        "bool" => Ok(ScalarType::Bool),
        "field" => Ok(ScalarType::Field),
        _ => Err(CompilerBackendError::UnsupportedType),
    }
}

fn identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn opcode(value: u8) -> Result<Opcode, CompilerBackendError> {
    match value {
        1 => Ok(Opcode::Parameter),
        2 => Ok(Opcode::Constant),
        3 => Ok(Opcode::Not),
        4 => Ok(Opcode::And),
        5 => Ok(Opcode::Or),
        6 => Ok(Opcode::Equal),
        7 => Ok(Opcode::NotEqual),
        12 => Ok(Opcode::Add),
        13 => Ok(Opcode::Subtract),
        14 => Ok(Opcode::Multiply),
        26 => Ok(Opcode::Assert),
        27 => Ok(Opcode::Return),
        8..=11 | 15..=25 => Err(CompilerBackendError::UnsupportedInstruction),
        _ => Err(CompilerBackendError::InvalidEncoding),
    }
}

impl CompilerProgram {
    pub fn decode(ir: &[u8]) -> Result<Self, CompilerBackendError> {
        if ir.len() > MAX_IR_BYTES {
            return Err(CompilerBackendError::LimitExceeded);
        }
        let mut reader = Reader {
            data: ir,
            offset: 0,
        };
        if reader.take(IR_DOMAIN.len())? != IR_DOMAIN {
            return Err(CompilerBackendError::InvalidEncoding);
        }
        let profile_digest: [u8; 32] = reader
            .take(32)?
            .try_into()
            .map_err(|_| CompilerBackendError::InvalidEncoding)?;
        let function_count =
            usize::try_from(reader.uleb()?).map_err(|_| CompilerBackendError::LimitExceeded)?;
        if function_count == 0 || function_count > MAX_FUNCTIONS || function_count != 1 {
            return Err(CompilerBackendError::UnsupportedInstruction);
        }
        let name = reader.text(128)?;
        if !identifier(&name) {
            return Err(CompilerBackendError::InvalidEncoding);
        }
        let exported = match reader.byte()? {
            0 => false,
            1 => true,
            _ => return Err(CompilerBackendError::InvalidEncoding),
        };
        if !exported {
            return Err(CompilerBackendError::InvalidProgram);
        }
        let parameter_count =
            usize::try_from(reader.uleb()?).map_err(|_| CompilerBackendError::LimitExceeded)?;
        if parameter_count > 4096 {
            return Err(CompilerBackendError::LimitExceeded);
        }
        let mut parameters = Vec::with_capacity(parameter_count);
        for _ in 0..parameter_count {
            let visibility = match reader.byte()? {
                1 => Visibility::Public,
                2 => Visibility::Private,
                _ => return Err(CompilerBackendError::InvalidEncoding),
            };
            let name = reader.text(128)?;
            if !identifier(&name) {
                return Err(CompilerBackendError::InvalidEncoding);
            }
            let kind = scalar_type(&reader.text(128)?)?;
            parameters.push(Parameter {
                visibility,
                name,
                kind,
            });
        }
        let return_type = scalar_type(&reader.text(128)?)?;
        let instruction_count =
            usize::try_from(reader.uleb()?).map_err(|_| CompilerBackendError::LimitExceeded)?;
        if instruction_count == 0 || instruction_count > MAX_INSTRUCTIONS {
            return Err(CompilerBackendError::LimitExceeded);
        }
        let mut instructions = Vec::with_capacity(instruction_count);
        for index in 0..instruction_count {
            let opcode = opcode(reader.byte()?)?;
            let encoded_result = reader.uleb()?;
            let result = if encoded_result == 0 {
                None
            } else {
                Some(
                    usize::try_from(encoded_result - 1)
                        .map_err(|_| CompilerBackendError::LimitExceeded)?,
                )
            };
            let kind = scalar_type(&reader.text(128)?)?;
            let operand_count =
                usize::try_from(reader.uleb()?).map_err(|_| CompilerBackendError::LimitExceeded)?;
            if operand_count > 64 {
                return Err(CompilerBackendError::LimitExceeded);
            }
            let mut operands = Vec::with_capacity(operand_count);
            for _ in 0..operand_count {
                let operand = usize::try_from(reader.uleb()?)
                    .map_err(|_| CompilerBackendError::LimitExceeded)?;
                if operand >= index {
                    return Err(CompilerBackendError::InvalidProgram);
                }
                operands.push(operand);
            }
            if reader.uleb()? != 0 {
                return Err(CompilerBackendError::UnsupportedInstruction); // guarded control flow
            }
            let encoded_immediate = reader.uleb()?;
            let immediate = if encoded_immediate == 0 {
                None
            } else {
                Some(encoded_immediate - 1)
            };
            let instruction_text = reader.text(8192)?;
            if opcode == Opcode::Parameter {
                let parameter = parameters
                    .get(index)
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                let visibility = if parameter.visibility == Visibility::Public {
                    "public:"
                } else {
                    "private:"
                };
                if instruction_text != visibility.to_owned() + &parameter.name {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            } else if !instruction_text.is_empty() {
                return Err(CompilerBackendError::UnsupportedInstruction);
            }
            let side_effect = matches!(opcode, Opcode::Assert | Opcode::Return);
            if side_effect != result.is_none() || result.is_some_and(|value| value != index) {
                return Err(CompilerBackendError::InvalidProgram);
            }
            instructions.push(Instruction {
                opcode,
                result,
                kind,
                operands,
                immediate,
            });
        }
        if reader.offset != ir.len()
            || !matches!(instructions.last().map(|i| i.opcode), Some(Opcode::Return))
        {
            return Err(CompilerBackendError::InvalidProgram);
        }
        validate_types(&parameters, return_type, &instructions)?;
        let ir_digest: [u8; 32] = Sha256::digest(ir).into();
        Ok(Self {
            profile_digest,
            ir_digest,
            function: Function {
                parameters,
                instructions,
            },
        })
    }

    pub fn public_input_count(&self) -> usize {
        self.function
            .parameters
            .iter()
            .filter(|p| p.visibility == Visibility::Public)
            .count()
            + 1
    }
}

fn validate_types(
    parameters: &[Parameter],
    return_type: ScalarType,
    instructions: &[Instruction],
) -> Result<(), CompilerBackendError> {
    let mut types: Vec<Option<ScalarType>> = Vec::with_capacity(instructions.len());
    let mut parameter_index = 0usize;
    let mut return_count = 0usize;
    for instruction in instructions {
        let operand_types: Vec<_> = instruction
            .operands
            .iter()
            .map(|index| types[*index].ok_or(CompilerBackendError::InvalidProgram))
            .collect::<Result<_, _>>()?;
        match instruction.opcode {
            Opcode::Parameter => {
                if parameter_index >= parameters.len()
                    || instruction.kind != parameters[parameter_index].kind
                    || !instruction.operands.is_empty()
                    || instruction.immediate.is_some()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
                parameter_index += 1;
            }
            Opcode::Constant => {
                if !instruction.operands.is_empty()
                    || instruction.immediate.is_none()
                    || (instruction.kind == ScalarType::Bool && instruction.immediate.unwrap() > 1)
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::Not => require(
                &operand_types,
                &[ScalarType::Bool],
                instruction.kind,
                ScalarType::Bool,
            )?,
            Opcode::And | Opcode::Or => require(
                &operand_types,
                &[ScalarType::Bool, ScalarType::Bool],
                instruction.kind,
                ScalarType::Bool,
            )?,
            Opcode::Equal | Opcode::NotEqual => {
                if operand_types.len() != 2
                    || operand_types[0] != operand_types[1]
                    || instruction.kind != ScalarType::Bool
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::Add | Opcode::Subtract | Opcode::Multiply => require(
                &operand_types,
                &[ScalarType::Field, ScalarType::Field],
                instruction.kind,
                ScalarType::Field,
            )?,
            Opcode::Assert => require(
                &operand_types,
                &[ScalarType::Bool],
                instruction.kind,
                ScalarType::Bool,
            )?,
            Opcode::Return => require(
                &operand_types,
                &[return_type],
                instruction.kind,
                return_type,
            )?,
        }
        match instruction.opcode {
            Opcode::Parameter | Opcode::Constant => {}
            _ if instruction.immediate.is_some() => {
                return Err(CompilerBackendError::InvalidProgram)
            }
            _ => {}
        }
        if instruction.opcode == Opcode::Return {
            return_count += 1;
        }
        types.push(instruction.result.map(|_| instruction.kind));
    }
    if parameter_index != parameters.len() || return_count != 1 {
        return Err(CompilerBackendError::InvalidProgram);
    }
    Ok(())
}

fn require(
    actual: &[ScalarType],
    expected: &[ScalarType],
    result: ScalarType,
    expected_result: ScalarType,
) -> Result<(), CompilerBackendError> {
    if actual != expected || result != expected_result {
        Err(CompilerBackendError::InvalidProgram)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct CompilerWitness {
    pub parameters: Vec<Fp>,
}

#[derive(Clone)]
struct CompilerCircuit {
    program: CompilerProgram,
    witness: Option<CompilerWitness>,
}

#[derive(Clone, Debug)]
struct CompilerConfig {
    left: Column<Advice>,
    right: Column<Advice>,
    output: Column<Advice>,
    inverse: Column<Advice>,
    instance: Column<Instance>,
    add: Selector,
    sub: Selector,
    mul: Selector,
    boolean: Selector,
    not: Selector,
    and: Selector,
    or: Selector,
    equal: Selector,
    not_equal: Selector,
    assert: Selector,
}

impl Circuit<Fp> for CompilerCircuit {
    type Config = CompilerConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            program: self.program.clone(),
            witness: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let left = meta.advice_column();
        let right = meta.advice_column();
        let output = meta.advice_column();
        let inverse = meta.advice_column();
        let constants = meta.fixed_column();
        let instance = meta.instance_column();
        for column in [left, right, output] {
            meta.enable_equality(column);
        }
        meta.enable_equality(instance);
        meta.enable_constant(constants);
        let add = meta.selector();
        let sub = meta.selector();
        let mul = meta.selector();
        let boolean = meta.selector();
        let not = meta.selector();
        let and = meta.selector();
        let or = meta.selector();
        let equal = meta.selector();
        let not_equal = meta.selector();
        let assert = meta.selector();
        meta.create_gate("compiler add", |meta| {
            let q = meta.query_selector(add);
            let a = meta.query_advice(left, Rotation::cur());
            let b = meta.query_advice(right, Rotation::cur());
            let out = meta.query_advice(output, Rotation::cur());
            vec![q * (a + b - out)]
        });
        meta.create_gate("compiler sub", |meta| {
            let q = meta.query_selector(sub);
            let a = meta.query_advice(left, Rotation::cur());
            let b = meta.query_advice(right, Rotation::cur());
            let out = meta.query_advice(output, Rotation::cur());
            vec![q * (a - b - out)]
        });
        meta.create_gate("compiler mul", |meta| {
            let q = meta.query_selector(mul);
            let a = meta.query_advice(left, Rotation::cur());
            let b = meta.query_advice(right, Rotation::cur());
            let out = meta.query_advice(output, Rotation::cur());
            vec![q * (a * b - out)]
        });
        meta.create_gate("compiler boolean", |meta| {
            let q = meta.query_selector(boolean);
            let out = meta.query_advice(output, Rotation::cur());
            vec![q * out.clone() * (out - halo2_proofs::plonk::Expression::Constant(Fp::one()))]
        });
        meta.create_gate("compiler not", |meta| {
            let q = meta.query_selector(not);
            let a = meta.query_advice(left, Rotation::cur());
            let out = meta.query_advice(output, Rotation::cur());
            vec![q * (a + out - halo2_proofs::plonk::Expression::Constant(Fp::one()))]
        });
        meta.create_gate("compiler and", |meta| {
            let q = meta.query_selector(and);
            let a = meta.query_advice(left, Rotation::cur());
            let b = meta.query_advice(right, Rotation::cur());
            let out = meta.query_advice(output, Rotation::cur());
            vec![q * (a * b - out)]
        });
        meta.create_gate("compiler or", |meta| {
            let q = meta.query_selector(or);
            let a = meta.query_advice(left, Rotation::cur());
            let b = meta.query_advice(right, Rotation::cur());
            let out = meta.query_advice(output, Rotation::cur());
            vec![q * (a.clone() + b.clone() - a * b - out)]
        });
        for (selector, inverted) in [(equal, false), (not_equal, true)] {
            meta.create_gate(
                if inverted {
                    "compiler not equal"
                } else {
                    "compiler equal"
                },
                |meta| {
                    let q = meta.query_selector(selector);
                    let a = meta.query_advice(left, Rotation::cur());
                    let b = meta.query_advice(right, Rotation::cur());
                    let out = meta.query_advice(output, Rotation::cur());
                    let inv = meta.query_advice(inverse, Rotation::cur());
                    let difference = a - b;
                    let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
                    let equality = if inverted {
                        one.clone() - out.clone()
                    } else {
                        out.clone()
                    };
                    vec![
                        q.clone() * equality.clone() * difference.clone(),
                        q * (difference * inv - (one - equality)),
                    ]
                },
            );
        }
        meta.create_gate("compiler assert", |meta| {
            let q = meta.query_selector(assert);
            let a = meta.query_advice(left, Rotation::cur());
            vec![q * (a - halo2_proofs::plonk::Expression::Constant(Fp::one()))]
        });
        CompilerConfig {
            left,
            right,
            output,
            inverse,
            instance,
            add,
            sub,
            mul,
            boolean,
            not,
            and,
            or,
            equal,
            not_equal,
            assert,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Commit otherwise non-semantic profile/IR identity into the fixed columns. This makes a
        // verification key specific to the complete canonical artifact, even when two artifacts
        // happen to lower to identical selector placement.
        for (index, chunk) in self
            .program
            .profile_digest
            .iter()
            .chain(self.program.ir_digest.iter())
            .copied()
            .collect::<Vec<_>>()
            .chunks_exact(8)
            .enumerate()
        {
            let limb = u64::from_le_bytes(chunk.try_into().unwrap());
            layouter.assign_region(
                || format!("compiler identity limb {index}"),
                |mut region| {
                    region.assign_advice_from_constant(
                        || "compiler identity",
                        config.output,
                        0,
                        Fp::from(limb),
                    )?;
                    Ok(())
                },
            )?;
        }
        let witness = self.witness.as_ref();
        if witness
            .is_some_and(|value| value.parameters.len() != self.program.function.parameters.len())
        {
            return Err(Error::Synthesis);
        }
        let mut parameter_index = 0usize;
        let mut public_index = 0usize;
        let mut values: Vec<Option<AssignedCell<Fp, Fp>>> =
            Vec::with_capacity(self.program.function.instructions.len());
        let mut returned: Option<AssignedCell<Fp, Fp>> = None;
        for (instruction_index, instruction) in
            self.program.function.instructions.iter().enumerate()
        {
            let operands: Vec<_> = instruction
                .operands
                .iter()
                .map(|index| values[*index].clone().unwrap())
                .collect();
            let assigned = layouter.assign_region(|| format!("compiler instruction {instruction_index}"), |mut region| {
                let copy = |cell: &AssignedCell<Fp, Fp>, column, region: &mut halo2_proofs::circuit::Region<'_, Fp>| {
                    cell.copy_advice(|| "operand", region, column, 0)
                };
                match instruction.opcode {
                    Opcode::Parameter => {
                        let value = witness.map_or(Value::unknown(), |w| Value::known(w.parameters[parameter_index]));
                        if instruction.kind == ScalarType::Bool { config.boolean.enable(&mut region, 0)?; }
                        region.assign_advice(|| "parameter", config.output, 0, || value)
                    }
                    Opcode::Constant => {
                        if instruction.kind == ScalarType::Bool { config.boolean.enable(&mut region, 0)?; }
                        region.assign_advice_from_constant(|| "constant", config.output, 0,
                            Fp::from(instruction.immediate.unwrap()))
                    },
                    Opcode::Not => { config.not.enable(&mut region, 0)?; config.boolean.enable(&mut region, 0)?;
                        let a = copy(&operands[0], config.left, &mut region)?;
                        region.assign_advice(|| "not", config.output, 0, || a.value().map(|v| Fp::one() - *v)) }
                    Opcode::And | Opcode::Or | Opcode::Add | Opcode::Subtract | Opcode::Multiply => {
                        let a = copy(&operands[0], config.left, &mut region)?;
                        let b = copy(&operands[1], config.right, &mut region)?;
                        let value = a.value().zip(b.value()).map(|(a, b)| match instruction.opcode {
                            Opcode::And | Opcode::Multiply => *a * *b, Opcode::Or => *a + *b - *a * *b,
                            Opcode::Add => *a + *b, Opcode::Subtract => *a - *b, _ => unreachable!(),
                        });
                        match instruction.opcode { Opcode::And => { config.and.enable(&mut region, 0)?; config.boolean.enable(&mut region, 0)?; },
                            Opcode::Or => { config.or.enable(&mut region, 0)?; config.boolean.enable(&mut region, 0)?; },
                            Opcode::Add => config.add.enable(&mut region, 0)?, Opcode::Subtract => config.sub.enable(&mut region, 0)?,
                            Opcode::Multiply => config.mul.enable(&mut region, 0)?, _ => unreachable!() }
                        region.assign_advice(|| "binary output", config.output, 0, || value)
                    }
                    Opcode::Equal | Opcode::NotEqual => {
                        let a = copy(&operands[0], config.left, &mut region)?;
                        let b = copy(&operands[1], config.right, &mut region)?;
                        let difference = a.value().zip(b.value()).map(|(a, b)| *a - *b);
                        let equality = difference.map(|d| if d == Fp::zero() { Fp::one() } else { Fp::zero() });
                        let output = if instruction.opcode == Opcode::Equal { equality } else { equality.map(|v| Fp::one() - v) };
                        let inverse = difference.map(|d| Option::<Fp>::from(d.invert()).unwrap_or(Fp::zero()));
                        region.assign_advice(|| "inverse", config.inverse, 0, || inverse)?;
                        config.boolean.enable(&mut region, 0)?;
                        if instruction.opcode == Opcode::Equal { config.equal.enable(&mut region, 0)?; }
                        else { config.not_equal.enable(&mut region, 0)?; }
                        region.assign_advice(|| "comparison", config.output, 0, || output)
                    }
                    Opcode::Assert => { config.assert.enable(&mut region, 0)?; copy(&operands[0], config.left, &mut region) }
                    Opcode::Return => copy(&operands[0], config.output, &mut region),
                }
            })?;
            if instruction.opcode == Opcode::Parameter {
                if self.program.function.parameters[parameter_index].visibility
                    == Visibility::Public
                {
                    layouter.constrain_instance(assigned.cell(), config.instance, public_index)?;
                    public_index += 1;
                }
                parameter_index += 1;
            }
            if instruction.opcode == Opcode::Return {
                returned = Some(assigned.clone());
            }
            values.push(Some(assigned));
        }
        layouter.constrain_instance(
            returned.ok_or(Error::Synthesis)?.cell(),
            config.instance,
            public_index,
        )
    }
}

pub fn compiler_vk_descriptor(ir: &[u8], k: u32) -> Result<Vec<u8>, CompilerBackendError> {
    let program = checked_program(ir, k)?;
    let circuit = CompilerCircuit {
        program: program.clone(),
        witness: None,
    };
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| CompilerBackendError::KeyGeneration)?;
    let pinned = format!("{:?}", vk.pinned());
    let mut hash = Sha256::new();
    hash.update(DESCRIPTOR_DOMAIN);
    hash.update(k.to_le_bytes());
    hash.update(program.profile_digest);
    hash.update(program.ir_digest);
    hash.update((pinned.len() as u64).to_le_bytes());
    hash.update(pinned.as_bytes());
    let mut descriptor = Vec::with_capacity(1 + 4 + 32 * 3);
    descriptor.push(1);
    descriptor.extend_from_slice(&k.to_le_bytes());
    descriptor.extend_from_slice(&program.profile_digest);
    descriptor.extend_from_slice(&program.ir_digest);
    descriptor.extend_from_slice(&hash.finalize());
    Ok(descriptor)
}

fn checked_program(ir: &[u8], k: u32) -> Result<CompilerProgram, CompilerBackendError> {
    if !(8..=20).contains(&k) {
        return Err(CompilerBackendError::LimitExceeded);
    }
    let program = CompilerProgram::decode(ir)?;
    if program.function.instructions.len() + 8 > (1usize << k) {
        return Err(CompilerBackendError::LimitExceeded);
    }
    Ok(program)
}

/// Creates a Halo2 proof for a canonical scalar ONXIR program.
///
/// `witness.parameters` contains every function parameter in declaration order. `public_inputs`
/// contains public parameters in declaration order followed by the public return value. The proof
/// uses fresh operating-system randomness; reproducibility is provided by the verification-key
/// descriptor, not by proof bytes.
pub fn create_compiler_proof(
    ir: &[u8],
    k: u32,
    witness: CompilerWitness,
    public_inputs: &[Fp],
) -> Result<Vec<u8>, CompilerBackendError> {
    let program = checked_program(ir, k)?;
    if witness.parameters.len() != program.function.parameters.len()
        || public_inputs.len() != program.public_input_count()
    {
        return Err(CompilerBackendError::InvalidWitness);
    }
    let mut public_index = 0usize;
    for (parameter_index, parameter) in program.function.parameters.iter().enumerate() {
        if parameter.kind == ScalarType::Bool
            && !matches!(witness.parameters[parameter_index], value if value == Fp::zero() || value == Fp::one())
        {
            return Err(CompilerBackendError::InvalidWitness);
        }
        if parameter.visibility == Visibility::Public {
            if witness.parameters[parameter_index] != public_inputs[public_index] {
                return Err(CompilerBackendError::InvalidWitness);
            }
            public_index += 1;
        }
    }
    let circuit = CompilerCircuit {
        program,
        witness: Some(witness),
    };
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| CompilerBackendError::KeyGeneration)?;
    let pk = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|_| CompilerBackendError::KeyGeneration)?;
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[public_inputs]],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|_| CompilerBackendError::ProofCreation)?;
    let proof = transcript.finalize();
    if proof.len() > MAX_PROOF_BYTES {
        return Err(CompilerBackendError::ProofTooLarge);
    }
    let mut reader = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&proof[..]);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[public_inputs]],
        &mut reader,
    )
    .map_err(|_| CompilerBackendError::ProofCreation)?;
    Ok(proof)
}

/// Verifies a proof against the verification key derived solely from canonical IR and `k`.
pub fn verify_compiler_proof(
    ir: &[u8],
    k: u32,
    public_inputs: &[Fp],
    proof: &[u8],
) -> Result<(), CompilerBackendError> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err(if proof.len() > MAX_PROOF_BYTES {
            CompilerBackendError::ProofTooLarge
        } else {
            CompilerBackendError::ProofVerification
        });
    }
    let program = checked_program(ir, k)?;
    if public_inputs.len() != program.public_input_count() {
        return Err(CompilerBackendError::InvalidWitness);
    }
    let circuit = CompilerCircuit {
        program,
        witness: None,
    };
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| CompilerBackendError::KeyGeneration)?;
    let mut reader = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(proof);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[public_inputs]],
        &mut reader,
    )
    .map_err(|_| CompilerBackendError::ProofVerification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn uleb(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            out.push(byte | if value == 0 { 0 } else { 0x80 });
            if value == 0 {
                return out;
            }
        }
    }
    fn text(value: &str) -> Vec<u8> {
        let mut out = uleb(value.len() as u64);
        out.extend_from_slice(value.as_bytes());
        out
    }
    fn instruction(
        opcode: u8,
        index: Option<usize>,
        kind: &str,
        operands: &[usize],
        immediate: Option<u64>,
        instruction_text: &str,
    ) -> Vec<u8> {
        let mut out = vec![opcode];
        out.extend(uleb(index.map_or(0, |v| v as u64 + 1)));
        out.extend(text(kind));
        out.extend(uleb(operands.len() as u64));
        for operand in operands {
            out.extend(uleb(*operand as u64));
        }
        out.push(0);
        out.extend(uleb(immediate.map_or(0, |v| v + 1)));
        out.extend(text(instruction_text));
        out
    }
    fn multiplication_ir() -> Vec<u8> {
        let mut ir = IR_DOMAIN.to_vec();
        ir.extend_from_slice(&[7u8; 32]);
        ir.push(1);
        ir.extend(text("multiply"));
        ir.push(1);
        ir.push(2);
        for (visibility, name) in [(1u8, "public_value"), (2u8, "secret")] {
            ir.push(visibility);
            ir.extend(text(name));
            ir.extend(text("field"));
        }
        ir.extend(text("field"));
        ir.push(4);
        ir.extend(instruction(
            1,
            Some(0),
            "field",
            &[],
            None,
            "public:public_value",
        ));
        ir.extend(instruction(
            1,
            Some(1),
            "field",
            &[],
            None,
            "private:secret",
        ));
        ir.extend(instruction(14, Some(2), "field", &[0, 1], None, ""));
        ir.extend(instruction(27, None, "field", &[2], None, ""));
        ir
    }

    #[test]
    fn scalar_ir_lowers_and_descriptor_is_deterministic() {
        let ir = multiplication_ir();
        let program = CompilerProgram::decode(&ir).unwrap();
        assert_eq!(program.public_input_count(), 2);
        let circuit = CompilerCircuit {
            program,
            witness: Some(CompilerWitness {
                parameters: vec![Fp::from(6), Fp::from(7)],
            }),
        };
        MockProver::run(8, &circuit, vec![vec![Fp::from(6), Fp::from(42)]])
            .unwrap()
            .assert_satisfied();
        assert!(
            MockProver::run(8, &circuit, vec![vec![Fp::from(6), Fp::from(41)]])
                .unwrap()
                .verify()
                .is_err()
        );
        assert_eq!(
            compiler_vk_descriptor(&ir, 8).unwrap(),
            compiler_vk_descriptor(&ir, 8).unwrap()
        );
    }

    #[test]
    fn backend_rejects_noncanonical_and_unsupported_ir() {
        let mut overlong = multiplication_ir();
        overlong[IR_DOMAIN.len() + 32] = 0x81;
        overlong.insert(IR_DOMAIN.len() + 33, 0);
        assert!(matches!(
            CompilerProgram::decode(&overlong),
            Err(CompilerBackendError::NonCanonicalInteger)
        ));
        let mut integer = multiplication_ir();
        let position = integer
            .windows(5)
            .position(|window| window == b"field")
            .unwrap();
        integer.splice(position..position + 5, b"u64".iter().copied());
        assert!(matches!(
            CompilerProgram::decode(&integer),
            Err(CompilerBackendError::UnsupportedType)
        ));
    }

    #[test]
    fn compiler_proof_round_trip_rejects_every_public_binding_mutation() {
        let ir = multiplication_ir();
        let public = [Fp::from(6), Fp::from(42)];
        let proof = create_compiler_proof(
            &ir,
            8,
            CompilerWitness {
                parameters: vec![Fp::from(6), Fp::from(7)],
            },
            &public,
        )
        .unwrap();
        verify_compiler_proof(&ir, 8, &public, &proof).unwrap();

        let wrong_return = [Fp::from(6), Fp::from(41)];
        assert!(matches!(
            verify_compiler_proof(&ir, 8, &wrong_return, &proof),
            Err(CompilerBackendError::ProofVerification)
        ));
        let mut altered_ir = ir.clone();
        altered_ir[IR_DOMAIN.len()] ^= 1;
        assert!(matches!(
            verify_compiler_proof(&altered_ir, 8, &public, &proof),
            Err(CompilerBackendError::ProofVerification)
        ));
        let mut corrupted = proof.clone();
        let corruption_index = corrupted.len() / 2;
        corrupted[corruption_index] ^= 1;
        assert!(matches!(
            verify_compiler_proof(&ir, 8, &public, &corrupted),
            Err(CompilerBackendError::ProofVerification)
        ));
        assert!(matches!(
            create_compiler_proof(
                &ir,
                8,
                CompilerWitness {
                    parameters: vec![Fp::from(5), Fp::from(7)],
                },
                &public,
            ),
            Err(CompilerBackendError::InvalidWitness)
        ));
    }
}
