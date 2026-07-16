//! Deterministic Halo2 lowering boundary for canonical `ONXIR` v1.
//!
//! This backend profile accepts an explicitly selected exported function over the bounded Onyx v1
//! language. Unsupported instructions fail closed. The circuit shape retains the decoded program in
//! `without_witnesses`, so key generation commits to opcode/selector placement rather than to runtime
//! witnesses.

use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
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
use std::collections::BTreeMap;

mod compiler_composites;

const IR_DOMAIN: &[u8] = b"ONXIR\x01";
const DESCRIPTOR_DOMAIN: &[u8] = b"bytecoin.onyx.compiler-halo2-descriptor.v2";
const EXPORT_DOMAIN: &[u8] = b"bytecoin.onyx.compiler-export.v1";
const MAX_IR_BYTES: usize = 64 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 1024;
const MAX_INSTRUCTIONS: usize = 1_000_000;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScalarType {
    Bool,
    Integer(u8),
    Field,
}

impl ScalarType {
    fn integer_bits(self) -> Option<u8> {
        match self {
            Self::Integer(bits) => Some(bits),
            _ => None,
        }
    }
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
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    ShiftLeft,
    ShiftRight,
    Call,
    Intrinsic,
    Select,
    Assert,
    Return,
}

#[derive(Clone, Debug)]
struct Instruction {
    opcode: Opcode,
    result: Option<usize>,
    kind: ScalarType,
    operands: Vec<usize>,
    guard: Option<usize>,
    immediate: Option<u64>,
    text: String,
}

#[derive(Clone, Debug)]
struct Function {
    name: String,
    exported: bool,
    parameters: Vec<Parameter>,
    return_types: Vec<ScalarType>,
    instructions: Vec<Instruction>,
}

#[derive(Clone, Debug)]
pub struct CompilerProgram {
    profile_digest: [u8; 32],
    ir_digest: [u8; 32],
    export_digest: [u8; 32],
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
        "u8" => Ok(ScalarType::Integer(8)),
        "u16" => Ok(ScalarType::Integer(16)),
        "u32" => Ok(ScalarType::Integer(32)),
        "u64" => Ok(ScalarType::Integer(64)),
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
        8 => Ok(Opcode::Less),
        9 => Ok(Opcode::LessEqual),
        10 => Ok(Opcode::Greater),
        11 => Ok(Opcode::GreaterEqual),
        12 => Ok(Opcode::Add),
        13 => Ok(Opcode::Subtract),
        14 => Ok(Opcode::Multiply),
        15 => Ok(Opcode::Divide),
        16 => Ok(Opcode::Remainder),
        17 => Ok(Opcode::ShiftLeft),
        18 => Ok(Opcode::ShiftRight),
        24 => Ok(Opcode::Intrinsic),
        25 => Ok(Opcode::Call),
        26 => Ok(Opcode::Assert),
        27 => Ok(Opcode::Return),
        19..=23 => Err(CompilerBackendError::UnsupportedInstruction),
        _ => Err(CompilerBackendError::InvalidEncoding),
    }
}

impl CompilerProgram {
    pub fn decode(ir: &[u8]) -> Result<Self, CompilerBackendError> {
        Self::decode_export(ir, None)
    }

    pub fn decode_export(ir: &[u8], export: Option<&str>) -> Result<Self, CompilerBackendError> {
        compiler_composites::decode_composite_program(ir, export)
    }

    #[allow(dead_code)]
    fn decode_legacy_scalar(ir: &[u8]) -> Result<Self, CompilerBackendError> {
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
        if function_count == 0 || function_count > MAX_FUNCTIONS {
            return Err(CompilerBackendError::LimitExceeded);
        }
        let mut functions = Vec::with_capacity(function_count);
        let mut signatures = BTreeMap::new();
        for _ in 0..function_count {
            let name = reader.text(128)?;
            if !identifier(&name) {
                return Err(CompilerBackendError::InvalidEncoding);
            }
            if signatures.contains_key(&name) {
                return Err(CompilerBackendError::InvalidProgram);
            }
            let exported = match reader.byte()? {
                0 => false,
                1 => true,
                _ => return Err(CompilerBackendError::InvalidEncoding),
            };
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
                let parameter_name = reader.text(128)?;
                if !identifier(&parameter_name) {
                    return Err(CompilerBackendError::InvalidEncoding);
                }
                let kind = scalar_type(&reader.text(128)?)?;
                parameters.push(Parameter {
                    visibility,
                    name: parameter_name,
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
                let operand_count = usize::try_from(reader.uleb()?)
                    .map_err(|_| CompilerBackendError::LimitExceeded)?;
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
                let encoded_guard = reader.uleb()?;
                let guard = if encoded_guard == 0 {
                    None
                } else {
                    let guard = usize::try_from(encoded_guard - 1)
                        .map_err(|_| CompilerBackendError::LimitExceeded)?;
                    if guard >= index {
                        return Err(CompilerBackendError::InvalidProgram);
                    }
                    Some(guard)
                };
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
                } else if opcode == Opcode::Call {
                    if !identifier(&instruction_text) || !signatures.contains_key(&instruction_text)
                    {
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
                    guard,
                    immediate,
                    text: instruction_text,
                });
            }
            if !matches!(instructions.last().map(|i| i.opcode), Some(Opcode::Return)) {
                return Err(CompilerBackendError::InvalidProgram);
            }
            validate_types(&parameters, return_type, &instructions, &signatures)?;
            signatures.insert(
                name.clone(),
                (
                    parameters.iter().map(|parameter| parameter.kind).collect(),
                    return_type,
                ),
            );
            functions.push(Function {
                name,
                exported,
                parameters,
                return_types: vec![return_type],
                instructions,
            });
        }
        if reader.offset != ir.len() {
            return Err(CompilerBackendError::InvalidProgram);
        }
        let exports: Vec<_> = functions
            .iter()
            .enumerate()
            .filter(|(_, function)| function.exported)
            .map(|(index, _)| index)
            .collect();
        if exports.len() != 1 {
            return Err(CompilerBackendError::UnsupportedInstruction);
        }
        let function = inline_export(&functions, exports[0])?;
        let ir_digest: [u8; 32] = Sha256::digest(ir).into();
        Ok(Self {
            profile_digest,
            ir_digest,
            export_digest: export_digest(&function.name),
            function,
        })
    }

    pub fn public_input_count(&self) -> usize {
        self.function
            .parameters
            .iter()
            .filter(|p| p.visibility == Visibility::Public)
            .count()
            + self.function.return_types.len()
    }

    fn estimated_rows(&self) -> Result<usize, CompilerBackendError> {
        self.function.instructions.iter().try_fold(
            self.function.instructions.len() + 16,
            |rows, instruction| {
                let result_range = instruction
                    .result
                    .and_then(|_| instruction.kind.integer_bits())
                    .map_or(0, usize::from);
                let ordering_rows = if matches!(
                    instruction.opcode,
                    Opcode::Less | Opcode::LessEqual | Opcode::Greater | Opcode::GreaterEqual
                ) {
                    instruction
                        .operands
                        .first()
                        .and_then(|operand| {
                            self.function.instructions[*operand].kind.integer_bits()
                        })
                        .map_or(0, |bits| usize::from(bits) + 1)
                } else {
                    0
                };
                let division_rows =
                    if matches!(instruction.opcode, Opcode::Divide | Opcode::Remainder)
                        && instruction.kind.integer_bits().is_some()
                    {
                        2 * usize::from(instruction.kind.integer_bits().unwrap()) + 3
                    } else {
                        0
                    };
                let shift_rows =
                    if matches!(instruction.opcode, Opcode::ShiftLeft | Opcode::ShiftRight) {
                        let bits = usize::from(instruction.kind.integer_bits().unwrap());
                        let power_bits =
                            instruction.kind.integer_bits().unwrap().trailing_zeros() as usize;
                        bits + bits
                            + power_bits
                            + if instruction.opcode == Opcode::ShiftRight {
                                2 * bits + 4
                            } else {
                                2
                            }
                    } else {
                        0
                    };
                let intrinsic_rows = if instruction.opcode == Opcode::Intrinsic {
                    match instruction.text.as_str() {
                        "poseidon_hash" => 96,
                        "merkle_root" => 192,
                        "nullifier" => 288,
                        _ => return Err(CompilerBackendError::InvalidProgram),
                    }
                } else {
                    0
                };
                rows.checked_add(
                    result_range + ordering_rows + division_rows + shift_rows + intrinsic_rows,
                )
                .ok_or(CompilerBackendError::LimitExceeded)
            },
        )
    }
}

fn inline_export(
    functions: &[Function],
    export_index: usize,
) -> Result<Function, CompilerBackendError> {
    fn inline_function(
        functions: &[Function],
        function_index: usize,
        arguments: Option<&[usize]>,
        inherited_guard: Option<usize>,
        output: &mut Vec<Instruction>,
    ) -> Result<usize, CompilerBackendError> {
        let function = &functions[function_index];
        if arguments.is_some_and(|arguments| arguments.len() != function.parameters.len()) {
            return Err(CompilerBackendError::InvalidProgram);
        }
        let mut mapping = vec![None; function.instructions.len()];
        let mut parameter_index = 0usize;
        for (old_index, instruction) in function.instructions.iter().enumerate() {
            if instruction.opcode == Opcode::Parameter {
                if let Some(arguments) = arguments {
                    mapping[old_index] = Some(arguments[parameter_index]);
                } else {
                    let new_index = output.len();
                    let mut cloned = instruction.clone();
                    cloned.result = Some(new_index);
                    output.push(cloned);
                    mapping[old_index] = Some(new_index);
                }
                parameter_index += 1;
                continue;
            }
            let operands: Vec<_> = instruction
                .operands
                .iter()
                .map(|operand| mapping[*operand].ok_or(CompilerBackendError::InvalidProgram))
                .collect::<Result<_, _>>()?;
            let own_guard = instruction
                .guard
                .map(|guard| mapping[guard].ok_or(CompilerBackendError::InvalidProgram))
                .transpose()?;
            let guard = match (inherited_guard, own_guard) {
                (Some(left), Some(right)) => {
                    let result = output.len();
                    output.push(Instruction {
                        opcode: Opcode::And,
                        result: Some(result),
                        kind: ScalarType::Bool,
                        operands: vec![left, right],
                        guard: None,
                        immediate: None,
                        text: String::new(),
                    });
                    Some(result)
                }
                (left, right) => left.or(right),
            };
            if instruction.opcode == Opcode::Call {
                let target_index = functions[..function_index]
                    .iter()
                    .position(|candidate| candidate.name == instruction.text)
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                mapping[old_index] = Some(inline_function(
                    functions,
                    target_index,
                    Some(&operands),
                    guard,
                    output,
                )?);
                continue;
            }
            if instruction.opcode == Opcode::Return {
                let returned = operands
                    .first()
                    .copied()
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                if let Some(guard) = inherited_guard {
                    let zero = output.len();
                    output.push(Instruction {
                        opcode: Opcode::Constant,
                        result: Some(zero),
                        kind: function.return_types[0],
                        operands: Vec::new(),
                        guard: None,
                        immediate: Some(0),
                        text: String::new(),
                    });
                    let selected = output.len();
                    output.push(Instruction {
                        opcode: Opcode::Select,
                        result: Some(selected),
                        kind: function.return_types[0],
                        operands: vec![guard, returned, zero],
                        guard: None,
                        immediate: None,
                        text: String::new(),
                    });
                    return Ok(selected);
                }
                return Ok(returned);
            }
            let new_index = output.len();
            let mut cloned = instruction.clone();
            cloned.operands = operands;
            cloned.guard = guard;
            cloned.result = instruction.result.map(|_| new_index);
            output.push(cloned);
            if instruction.result.is_some() {
                mapping[old_index] = Some(new_index);
            }
            if output.len() > MAX_INSTRUCTIONS {
                return Err(CompilerBackendError::LimitExceeded);
            }
        }
        Err(CompilerBackendError::InvalidProgram)
    }

    let export = &functions[export_index];
    let mut instructions = Vec::new();
    let returned = inline_function(functions, export_index, None, None, &mut instructions)?;
    instructions.push(Instruction {
        opcode: Opcode::Return,
        result: None,
        kind: export.return_types[0],
        operands: vec![returned],
        guard: None,
        immediate: None,
        text: String::new(),
    });
    lower_guards(Function {
        name: export.name.clone(),
        exported: true,
        parameters: export.parameters.clone(),
        return_types: export.return_types.clone(),
        instructions,
    })
}

fn lower_guards(mut function: Function) -> Result<Function, CompilerBackendError> {
    fn push_value(output: &mut Vec<Instruction>, mut instruction: Instruction) -> usize {
        let index = output.len();
        instruction.result = Some(index);
        output.push(instruction);
        index
    }
    fn constant(output: &mut Vec<Instruction>, kind: ScalarType, value: u64) -> usize {
        push_value(
            output,
            Instruction {
                opcode: Opcode::Constant,
                result: None,
                kind,
                operands: Vec::new(),
                guard: None,
                immediate: Some(value),
                text: String::new(),
            },
        )
    }
    fn select(
        output: &mut Vec<Instruction>,
        guard: usize,
        when_true: usize,
        when_false: usize,
        kind: ScalarType,
    ) -> usize {
        push_value(
            output,
            Instruction {
                opcode: Opcode::Select,
                result: None,
                kind,
                operands: vec![guard, when_true, when_false],
                guard: None,
                immediate: None,
                text: String::new(),
            },
        )
    }

    let original = std::mem::take(&mut function.instructions);
    let mut output = Vec::with_capacity(original.len());
    let mut mapping = vec![None; original.len()];
    for (old_index, instruction) in original.into_iter().enumerate() {
        let operands: Vec<_> = instruction
            .operands
            .iter()
            .map(|operand| mapping[*operand].ok_or(CompilerBackendError::InvalidProgram))
            .collect::<Result<_, _>>()?;
        let guard = instruction
            .guard
            .map(|guard| mapping[guard].ok_or(CompilerBackendError::InvalidProgram))
            .transpose()?;
        if instruction.opcode == Opcode::Return {
            output.push(Instruction {
                operands,
                guard: None,
                ..instruction
            });
            continue;
        }
        if let Some(guard) = guard {
            if instruction.opcode == Opcode::Assert {
                let not_guard = push_value(
                    &mut output,
                    Instruction {
                        opcode: Opcode::Not,
                        result: None,
                        kind: ScalarType::Bool,
                        operands: vec![guard],
                        guard: None,
                        immediate: None,
                        text: String::new(),
                    },
                );
                let implication = push_value(
                    &mut output,
                    Instruction {
                        opcode: Opcode::Or,
                        result: None,
                        kind: ScalarType::Bool,
                        operands: vec![not_guard, operands[0]],
                        guard: None,
                        immediate: None,
                        text: String::new(),
                    },
                );
                output.push(Instruction {
                    operands: vec![implication],
                    guard: None,
                    ..instruction
                });
                continue;
            }
            let mut safe_operands = Vec::with_capacity(operands.len());
            for (operand_index, operand) in operands.iter().copied().enumerate() {
                let operand_kind = output[operand].kind;
                let default = constant(
                    &mut output,
                    operand_kind,
                    u64::from(
                        matches!(instruction.opcode, Opcode::Divide | Opcode::Remainder)
                            && operand_index == 1,
                    ),
                );
                safe_operands.push(select(&mut output, guard, operand, default, operand_kind));
            }
            let raw = push_value(
                &mut output,
                Instruction {
                    operands: safe_operands,
                    guard: None,
                    ..instruction.clone()
                },
            );
            let neutral = constant(&mut output, instruction.kind, 0);
            mapping[old_index] = Some(select(&mut output, guard, raw, neutral, instruction.kind));
        } else {
            let result = instruction.result.map(|_| output.len());
            output.push(Instruction {
                result,
                operands,
                guard: None,
                ..instruction
            });
            if result.is_some() {
                mapping[old_index] = result;
            }
        }
        if output.len() > MAX_INSTRUCTIONS {
            return Err(CompilerBackendError::LimitExceeded);
        }
    }
    function.instructions = output;
    Ok(function)
}

fn validate_types(
    parameters: &[Parameter],
    return_type: ScalarType,
    instructions: &[Instruction],
    signatures: &BTreeMap<String, (Vec<ScalarType>, ScalarType)>,
) -> Result<(), CompilerBackendError> {
    let mut types: Vec<Option<ScalarType>> = Vec::with_capacity(instructions.len());
    let mut parameter_index = 0usize;
    let mut return_count = 0usize;
    for instruction in instructions {
        if instruction
            .guard
            .is_some_and(|guard| types[guard] != Some(ScalarType::Bool))
            || matches!(instruction.opcode, Opcode::Parameter | Opcode::Return)
                && instruction.guard.is_some()
        {
            return Err(CompilerBackendError::InvalidProgram);
        }
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
                    || instruction.kind.integer_bits().is_some_and(|bits| {
                        bits < 64 && instruction.immediate.unwrap() >= (1u64 << bits)
                    })
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
            Opcode::Less | Opcode::LessEqual | Opcode::Greater | Opcode::GreaterEqual => {
                if operand_types.len() != 2
                    || operand_types[0] != operand_types[1]
                    || operand_types[0].integer_bits().is_none()
                    || instruction.kind != ScalarType::Bool
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::Add | Opcode::Subtract | Opcode::Multiply => {
                if operand_types != [instruction.kind, instruction.kind]
                    || (instruction.kind != ScalarType::Field
                        && instruction.kind.integer_bits().is_none())
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::Divide => {
                if operand_types != [instruction.kind, instruction.kind]
                    || (instruction.kind != ScalarType::Field
                        && instruction.kind.integer_bits().is_none())
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::Remainder => {
                if operand_types != [instruction.kind, instruction.kind]
                    || instruction.kind.integer_bits().is_none()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::ShiftLeft | Opcode::ShiftRight => {
                if operand_types != [instruction.kind, instruction.kind]
                    || instruction.kind.integer_bits().is_none()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::Call => {
                let (expected_parameters, expected_return) = signatures
                    .get(&instruction.text)
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                if &operand_types != expected_parameters || instruction.kind != *expected_return {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::Intrinsic => {
                let expected = match instruction.text.as_str() {
                    "poseidon_hash" | "merkle_root" => 2,
                    "nullifier" => 3,
                    _ => return Err(CompilerBackendError::InvalidProgram),
                };
                if operand_types != vec![ScalarType::Field; expected]
                    || instruction.kind != ScalarType::Field
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            Opcode::Select => {
                if operand_types != [ScalarType::Bool, instruction.kind, instruction.kind] {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
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

#[derive(Clone)]
struct CompilerConfig {
    left: Column<Advice>,
    right: Column<Advice>,
    output: Column<Advice>,
    inverse: Column<Advice>,
    auxiliary: Column<Advice>,
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
    range_step: Selector,
    less: Selector,
    not_less: Selector,
    field_divide: Selector,
    integer_divide: Selector,
    zero: Selector,
    shift_power: Selector,
    select: Selector,
    poseidon: Pow5Config<Fp, 3, 2>,
    poseidon_state: [Column<Advice>; 3],
}

fn canonical_u64(value: &Fp) -> Option<u64> {
    let representation = value.to_repr();
    let bytes = representation.as_ref();
    if bytes[8..].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
}

fn two_pow(bits: u8) -> Fp {
    (0..bits).fold(Fp::one(), |value, _| value + value)
}

fn decompose_integer(
    layouter: &mut impl Layouter<Fp>,
    config: &CompilerConfig,
    cell: &AssignedCell<Fp, Fp>,
    bits: u8,
    label: String,
) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
    let integer = cell.value().map(|value| canonical_u64(value).unwrap_or(0));
    let mut decomposition = layouter.assign_region(
        || label.clone(),
        |mut region| {
            let mut decomposition = Vec::with_capacity(usize::from(bits));
            let mut accumulator = region.assign_advice_from_constant(
                || "range accumulator zero",
                config.left,
                0,
                Fp::zero(),
            )?;
            for row in 0..usize::from(bits) {
                if row != 0 {
                    accumulator = accumulator.copy_advice(
                        || "range accumulator",
                        &mut region,
                        config.left,
                        row,
                    )?;
                }
                let bit_index = usize::from(bits) - row - 1;
                let bit = integer.map(|value| Fp::from((value >> bit_index) & 1));
                decomposition.push(region.assign_advice(
                    || "range bit",
                    config.right,
                    row,
                    || bit,
                )?);
                config.range_step.enable(&mut region, row)?;
                accumulator = if row + 1 == usize::from(bits) {
                    cell.copy_advice(|| "range checked value", &mut region, config.output, row)?
                } else {
                    region.assign_advice(
                        || "next range accumulator",
                        config.output,
                        row,
                        || {
                            accumulator
                                .value()
                                .zip(bit)
                                .map(|(acc, bit)| *acc * Fp::from(2) + bit)
                        },
                    )?
                };
            }
            Ok(decomposition)
        },
    )?;
    decomposition.reverse();
    Ok(decomposition)
}

fn range_check(
    layouter: &mut impl Layouter<Fp>,
    config: &CompilerConfig,
    cell: &AssignedCell<Fp, Fp>,
    bits: u8,
    label: String,
) -> Result<(), Error> {
    decompose_integer(layouter, config, cell, bits, label).map(|_| ())
}

fn constrain_ordering(
    layouter: &mut impl Layouter<Fp>,
    config: &CompilerConfig,
    left: &AssignedCell<Fp, Fp>,
    right: &AssignedCell<Fp, Fp>,
    result: &AssignedCell<Fp, Fp>,
    bits: u8,
    inverted: bool,
    label: String,
) -> Result<(), Error> {
    let difference = left.value().zip(right.value()).map(|(left, right)| {
        let left = canonical_u64(left).unwrap_or(0);
        let right = canonical_u64(right).unwrap_or(0);
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        Fp::from(left.wrapping_sub(right) & mask)
    });
    let difference_cell = layouter.assign_region(
        || label.clone(),
        |mut region| {
            left.copy_advice(|| "ordered left", &mut region, config.left, 0)?;
            right.copy_advice(|| "ordered right", &mut region, config.right, 0)?;
            result.copy_advice(|| "ordered result", &mut region, config.inverse, 0)?;
            region.assign_advice_from_constant(
                || "integer modulus",
                config.auxiliary,
                0,
                two_pow(bits),
            )?;
            if inverted {
                config.not_less.enable(&mut region, 0)?;
            } else {
                config.less.enable(&mut region, 0)?;
            }
            region.assign_advice(|| "ordered difference", config.output, 0, || difference)
        },
    )?;
    range_check(
        layouter,
        config,
        &difference_cell,
        bits,
        format!("{label} difference range"),
    )
}

fn constrain_integer_division(
    layouter: &mut impl Layouter<Fp>,
    config: &CompilerConfig,
    numerator: &AssignedCell<Fp, Fp>,
    denominator: &AssignedCell<Fp, Fp>,
    result: &AssignedCell<Fp, Fp>,
    bits: u8,
    result_is_remainder: bool,
    label: String,
) -> Result<(), Error> {
    let quotient = numerator
        .value()
        .zip(denominator.value())
        .map(|(numerator, denominator)| {
            let numerator = canonical_u64(numerator).unwrap_or(0);
            let denominator = canonical_u64(denominator).unwrap_or(0);
            Fp::from(if denominator == 0 {
                0
            } else {
                numerator / denominator
            })
        });
    let remainder = numerator
        .value()
        .zip(denominator.value())
        .map(|(numerator, denominator)| {
            let numerator = canonical_u64(numerator).unwrap_or(0);
            let denominator = canonical_u64(denominator).unwrap_or(0);
            Fp::from(if denominator == 0 {
                0
            } else {
                numerator % denominator
            })
        });
    let denominator_inverse = denominator
        .value()
        .map(|denominator| Option::<Fp>::from(denominator.invert()).unwrap_or(Fp::zero()));
    let (quotient_cell, remainder_cell) = layouter.assign_region(
        || label.clone(),
        |mut region| {
            numerator.copy_advice(|| "division numerator", &mut region, config.left, 0)?;
            denominator.copy_advice(|| "division denominator", &mut region, config.right, 0)?;
            let (quotient_cell, remainder_cell) = if result_is_remainder {
                (
                    region.assign_advice(|| "division quotient", config.output, 0, || quotient)?,
                    result.copy_advice(|| "division remainder", &mut region, config.inverse, 0)?,
                )
            } else {
                (
                    result.copy_advice(|| "division quotient", &mut region, config.output, 0)?,
                    region.assign_advice(
                        || "division remainder",
                        config.inverse,
                        0,
                        || remainder,
                    )?,
                )
            };
            region.assign_advice(
                || "division denominator inverse",
                config.auxiliary,
                0,
                || denominator_inverse,
            )?;
            config.integer_divide.enable(&mut region, 0)?;
            Ok((quotient_cell, remainder_cell))
        },
    )?;
    let companion = if result_is_remainder {
        &quotient_cell
    } else {
        &remainder_cell
    };
    range_check(
        layouter,
        config,
        companion,
        bits,
        format!("{label} companion range"),
    )?;
    let true_cell = layouter.assign_region(
        || format!("{label} remainder bound truth"),
        |mut region| region.assign_advice_from_constant(|| "true", config.output, 0, Fp::one()),
    )?;
    constrain_ordering(
        layouter,
        config,
        &remainder_cell,
        denominator,
        &true_cell,
        bits,
        false,
        format!("{label} remainder bound"),
    )
}

fn constrain_shift(
    layouter: &mut impl Layouter<Fp>,
    config: &CompilerConfig,
    value: &AssignedCell<Fp, Fp>,
    count: &AssignedCell<Fp, Fp>,
    result: &AssignedCell<Fp, Fp>,
    bits: u8,
    right_shift: bool,
    label: String,
) -> Result<(), Error> {
    let count_bits =
        decompose_integer(layouter, config, count, bits, format!("{label} count bits"))?;
    let active_bits = bits.trailing_zeros() as usize;
    for (index, bit) in count_bits.iter().enumerate().skip(active_bits) {
        layouter.assign_region(
            || format!("{label} count high bit {index}"),
            |mut region| {
                bit.copy_advice(|| "invalid shift bit", &mut region, config.left, 0)?;
                config.zero.enable(&mut region, 0)
            },
        )?;
    }
    let mut power = layouter.assign_region(
        || format!("{label} power one"),
        |mut region| {
            region.assign_advice_from_constant(|| "shift power one", config.output, 0, Fp::one())
        },
    )?;
    for (index, bit) in count_bits.iter().take(active_bits).enumerate() {
        power = layouter.assign_region(
            || format!("{label} power bit {index}"),
            |mut region| {
                power.copy_advice(|| "previous shift power", &mut region, config.left, 0)?;
                bit.copy_advice(|| "shift count bit", &mut region, config.right, 0)?;
                let multiplier = two_pow(1u8 << index) - Fp::one();
                region.assign_advice_from_constant(
                    || "shift power multiplier",
                    config.auxiliary,
                    0,
                    multiplier,
                )?;
                config.shift_power.enable(&mut region, 0)?;
                let next = power
                    .value()
                    .zip(bit.value())
                    .map(|(power, bit)| *power * (Fp::one() + *bit * multiplier));
                region.assign_advice(|| "next shift power", config.output, 0, || next)
            },
        )?;
    }
    if right_shift {
        constrain_integer_division(
            layouter,
            config,
            value,
            &power,
            result,
            bits,
            false,
            format!("{label} right division"),
        )
    } else {
        layouter.assign_region(
            || format!("{label} left multiplication"),
            |mut region| {
                value.copy_advice(|| "shift value", &mut region, config.left, 0)?;
                power.copy_advice(|| "shift power", &mut region, config.right, 0)?;
                result.copy_advice(|| "shift result", &mut region, config.output, 0)?;
                config.mul.enable(&mut region, 0)
            },
        )
    }
}

fn compiler_hash2(
    config: &CompilerConfig,
    mut layouter: impl Layouter<Fp>,
    first: &AssignedCell<Fp, Fp>,
    second: &AssignedCell<Fp, Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let message = layouter.assign_region(
        || "compiler intrinsic message",
        |mut region| {
            Ok([
                first.copy_advice(
                    || "intrinsic first",
                    &mut region,
                    config.poseidon_state[0],
                    0,
                )?,
                second.copy_advice(
                    || "intrinsic second",
                    &mut region,
                    config.poseidon_state[1],
                    0,
                )?,
            ])
        },
    )?;
    PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
        Pow5Chip::construct(config.poseidon.clone()),
        layouter.namespace(|| "compiler intrinsic init"),
    )?
    .hash(layouter.namespace(|| "compiler intrinsic hash"), message)
}

fn compiler_intrinsic(
    config: &CompilerConfig,
    mut layouter: impl Layouter<Fp>,
    name: &str,
    operands: &[AssignedCell<Fp, Fp>],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let inner = compiler_hash2(
        config,
        layouter.namespace(|| format!("{name} inner")),
        &operands[0],
        &operands[1],
    )?;
    match name {
        "poseidon_hash" => Ok(inner),
        "merkle_root" => {
            let tag = layouter.assign_region(
                || "Merkle node tag",
                |mut region| {
                    region.assign_advice_from_constant(|| "tag", config.output, 0, Fp::from(2))
                },
            )?;
            compiler_hash2(
                config,
                layouter.namespace(|| "domain-separated Merkle node"),
                &tag,
                &inner,
            )
        }
        "nullifier" => {
            let positioned = compiler_hash2(
                config,
                layouter.namespace(|| "nullifier position"),
                &inner,
                &operands[2],
            )?;
            let tag = layouter.assign_region(
                || "nullifier tag",
                |mut region| {
                    region.assign_advice_from_constant(|| "tag", config.output, 0, Fp::from(3))
                },
            )?;
            compiler_hash2(
                config,
                layouter.namespace(|| "domain-separated nullifier"),
                &tag,
                &positioned,
            )
        }
        _ => Err(Error::Synthesis),
    }
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
        let auxiliary = meta.advice_column();
        let constants = meta.fixed_column();
        let instance = meta.instance_column();
        for column in [left, right, output, inverse, auxiliary] {
            meta.enable_equality(column);
        }
        meta.enable_equality(instance);
        meta.enable_constant(constants);
        let poseidon_state = std::array::from_fn(|_| meta.advice_column());
        let poseidon_partial_sbox = meta.advice_column();
        let poseidon_rc_a = std::array::from_fn(|_| meta.fixed_column());
        let poseidon_rc_b = std::array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(poseidon_rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            poseidon_state,
            poseidon_partial_sbox,
            poseidon_rc_a,
            poseidon_rc_b,
        );
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
        let range_step = meta.selector();
        let less = meta.selector();
        let not_less = meta.selector();
        let field_divide = meta.selector();
        let integer_divide = meta.selector();
        let zero = meta.selector();
        let shift_power = meta.selector();
        let select = meta.selector();
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
        meta.create_gate("compiler unsigned range step", |meta| {
            let q = meta.query_selector(range_step);
            let accumulator = meta.query_advice(left, Rotation::cur());
            let bit = meta.query_advice(right, Rotation::cur());
            let next = meta.query_advice(output, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
            let two = halo2_proofs::plonk::Expression::Constant(Fp::from(2));
            vec![
                q.clone() * (accumulator * two + bit.clone() - next),
                q * bit.clone() * (bit - one),
            ]
        });
        for (selector, inverted) in [(less, false), (not_less, true)] {
            meta.create_gate(
                if inverted {
                    "compiler unsigned not-less"
                } else {
                    "compiler unsigned less"
                },
                |meta| {
                    let q = meta.query_selector(selector);
                    let a = meta.query_advice(left, Rotation::cur());
                    let b = meta.query_advice(right, Rotation::cur());
                    let difference = meta.query_advice(output, Rotation::cur());
                    let result = meta.query_advice(inverse, Rotation::cur());
                    let modulus = meta.query_advice(auxiliary, Rotation::cur());
                    let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
                    let borrow = if inverted { one - result } else { result };
                    vec![q * (a - b + borrow * modulus - difference)]
                },
            );
        }
        meta.create_gate("compiler field divide", |meta| {
            let q = meta.query_selector(field_divide);
            let numerator = meta.query_advice(left, Rotation::cur());
            let denominator = meta.query_advice(right, Rotation::cur());
            let quotient = meta.query_advice(output, Rotation::cur());
            let denominator_inverse = meta.query_advice(inverse, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
            vec![
                q.clone() * (denominator.clone() * quotient - numerator),
                q * (denominator * denominator_inverse - one),
            ]
        });
        meta.create_gate("compiler integer divide", |meta| {
            let q = meta.query_selector(integer_divide);
            let numerator = meta.query_advice(left, Rotation::cur());
            let denominator = meta.query_advice(right, Rotation::cur());
            let quotient = meta.query_advice(output, Rotation::cur());
            let remainder = meta.query_advice(inverse, Rotation::cur());
            let denominator_inverse = meta.query_advice(auxiliary, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
            vec![
                q.clone() * (quotient * denominator.clone() + remainder - numerator),
                q * (denominator * denominator_inverse - one),
            ]
        });
        meta.create_gate("compiler zero", |meta| {
            let q = meta.query_selector(zero);
            let value = meta.query_advice(left, Rotation::cur());
            vec![q * value]
        });
        meta.create_gate("compiler shift power", |meta| {
            let q = meta.query_selector(shift_power);
            let previous = meta.query_advice(left, Rotation::cur());
            let bit = meta.query_advice(right, Rotation::cur());
            let next = meta.query_advice(output, Rotation::cur());
            let multiplier = meta.query_advice(auxiliary, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
            vec![q * (previous * (one + bit * multiplier) - next)]
        });
        meta.create_gate("compiler guarded select", |meta| {
            let q = meta.query_selector(select);
            let guard = meta.query_advice(left, Rotation::cur());
            let when_true = meta.query_advice(right, Rotation::cur());
            let when_false = meta.query_advice(auxiliary, Rotation::cur());
            let output = meta.query_advice(output, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
            vec![q * (guard.clone() * when_true + (one - guard) * when_false - output)]
        });
        CompilerConfig {
            left,
            right,
            output,
            inverse,
            auxiliary,
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
            range_step,
            less,
            not_less,
            field_divide,
            integer_divide,
            zero,
            shift_power,
            select,
            poseidon,
            poseidon_state,
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
            .chain(self.program.export_digest.iter())
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
        let mut returned: Vec<AssignedCell<Fp, Fp>> = Vec::new();
        for (instruction_index, instruction) in
            self.program.function.instructions.iter().enumerate()
        {
            let operands: Vec<_> = instruction
                .operands
                .iter()
                .map(|index| values[*index].clone().unwrap())
                .collect();
            let assigned = if instruction.opcode == Opcode::Intrinsic {
                compiler_intrinsic(
                    &config,
                    layouter.namespace(|| format!("compiler intrinsic {instruction_index}")),
                    &instruction.text,
                    &operands,
                )?
            } else {
                layouter.assign_region(|| format!("compiler instruction {instruction_index}"), |mut region| {
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
                    Opcode::Divide | Opcode::Remainder => {
                        let a = copy(&operands[0], config.left, &mut region)?;
                        let b = copy(&operands[1], config.right, &mut region)?;
                        if instruction.kind == ScalarType::Field {
                            let inverse = b.value().map(|value| {
                                Option::<Fp>::from(value.invert()).unwrap_or(Fp::zero())
                            });
                            region.assign_advice(
                                || "field denominator inverse",
                                config.inverse,
                                0,
                                || inverse,
                            )?;
                            config.field_divide.enable(&mut region, 0)?;
                            region.assign_advice(
                                || "field quotient",
                                config.output,
                                0,
                                || a.value().zip(inverse).map(|(a, inverse)| *a * inverse),
                            )
                        } else {
                            let value = a.value().zip(b.value()).map(|(a, b)| {
                                let a = canonical_u64(a).unwrap_or(0);
                                let b = canonical_u64(b).unwrap_or(0);
                                Fp::from(if b == 0 {
                                    0
                                } else if instruction.opcode == Opcode::Divide {
                                    a / b
                                } else {
                                    a % b
                                })
                            });
                            region.assign_advice(
                                || "integer division output",
                                config.output,
                                0,
                                || value,
                            )
                        }
                    }
                    Opcode::ShiftLeft | Opcode::ShiftRight => {
                        let a = copy(&operands[0], config.left, &mut region)?;
                        let b = copy(&operands[1], config.right, &mut region)?;
                        let value = a.value().zip(b.value()).map(|(a, b)| {
                            let a = canonical_u64(a).unwrap_or(0);
                            let b = canonical_u64(b).unwrap_or(u64::MAX);
                            Fp::from(if b >= u64::from(instruction.kind.integer_bits().unwrap()) {
                                0
                            } else if instruction.opcode == Opcode::ShiftLeft {
                                a.checked_shl(b as u32).unwrap_or(0)
                            } else {
                                a >> b
                            })
                        });
                        region.assign_advice(
                            || "integer shift output",
                            config.output,
                            0,
                            || value,
                        )
                    }
                    Opcode::Call | Opcode::Intrinsic => return Err(Error::Synthesis),
                    Opcode::Select => {
                        let guard = copy(&operands[0], config.left, &mut region)?;
                        let when_true = copy(&operands[1], config.right, &mut region)?;
                        let when_false = copy(&operands[2], config.auxiliary, &mut region)?;
                        config.select.enable(&mut region, 0)?;
                        region.assign_advice(
                            || "guarded selection",
                            config.output,
                            0,
                            || guard.value().zip(when_true.value()).zip(when_false.value()).map(
                                |((guard, when_true), when_false)| {
                                    *guard * *when_true + (Fp::one() - *guard) * *when_false
                                },
                            ),
                        )
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
                    Opcode::Less | Opcode::LessEqual | Opcode::Greater | Opcode::GreaterEqual => {
                        config.boolean.enable(&mut region, 0)?;
                        let output = operands[0].value().zip(operands[1].value()).map(|(left, right)| {
                            let left = canonical_u64(left).unwrap_or(0);
                            let right = canonical_u64(right).unwrap_or(0);
                            Fp::from(match instruction.opcode {
                                Opcode::Less => left < right,
                                Opcode::LessEqual => left <= right,
                                Opcode::Greater => left > right,
                                Opcode::GreaterEqual => left >= right,
                                _ => unreachable!(),
                            } as u64)
                        });
                        region.assign_advice(|| "ordered comparison", config.output, 0, || output)
                    }
                    Opcode::Assert => { config.assert.enable(&mut region, 0)?; copy(&operands[0], config.left, &mut region) }
                    Opcode::Return => copy(&operands[0], config.output, &mut region),
                }
                })?
            };
            if instruction.result.is_some() {
                if let Some(bits) = instruction.kind.integer_bits() {
                    range_check(
                        &mut layouter,
                        &config,
                        &assigned,
                        bits,
                        format!("compiler u{bits} range {instruction_index}"),
                    )?;
                }
            }
            if matches!(
                instruction.opcode,
                Opcode::Less | Opcode::LessEqual | Opcode::Greater | Opcode::GreaterEqual
            ) {
                let bits = self.program.function.instructions[instruction.operands[0]]
                    .kind
                    .integer_bits()
                    .ok_or(Error::Synthesis)?;
                let (left, right, inverted) = match instruction.opcode {
                    Opcode::Less => (&operands[0], &operands[1], false),
                    Opcode::LessEqual => (&operands[1], &operands[0], true),
                    Opcode::Greater => (&operands[1], &operands[0], false),
                    Opcode::GreaterEqual => (&operands[0], &operands[1], true),
                    _ => unreachable!(),
                };
                constrain_ordering(
                    &mut layouter,
                    &config,
                    left,
                    right,
                    &assigned,
                    bits,
                    inverted,
                    format!("compiler ordering {instruction_index}"),
                )?;
            }
            if matches!(instruction.opcode, Opcode::Divide | Opcode::Remainder)
                && instruction.kind.integer_bits().is_some()
            {
                constrain_integer_division(
                    &mut layouter,
                    &config,
                    &operands[0],
                    &operands[1],
                    &assigned,
                    instruction.kind.integer_bits().unwrap(),
                    instruction.opcode == Opcode::Remainder,
                    format!("compiler integer division {instruction_index}"),
                )?;
            }
            if matches!(instruction.opcode, Opcode::ShiftLeft | Opcode::ShiftRight) {
                constrain_shift(
                    &mut layouter,
                    &config,
                    &operands[0],
                    &operands[1],
                    &assigned,
                    instruction.kind.integer_bits().unwrap(),
                    instruction.opcode == Opcode::ShiftRight,
                    format!("compiler shift {instruction_index}"),
                )?;
            }
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
                returned.push(assigned.clone());
            }
            values.push(Some(assigned));
        }
        if returned.len() != self.program.function.return_types.len() {
            return Err(Error::Synthesis);
        }
        for returned in returned {
            layouter.constrain_instance(returned.cell(), config.instance, public_index)?;
            public_index += 1;
        }
        Ok(())
    }
}

fn export_digest(export: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(EXPORT_DOMAIN);
    hash.update((export.len() as u64).to_le_bytes());
    hash.update(export.as_bytes());
    hash.finalize().into()
}

pub fn compiler_vk_descriptor(ir: &[u8], k: u32) -> Result<Vec<u8>, CompilerBackendError> {
    compiler_vk_descriptor_selected(ir, k, None)
}

pub fn compiler_vk_descriptor_for_export(
    ir: &[u8],
    k: u32,
    export: &str,
) -> Result<Vec<u8>, CompilerBackendError> {
    compiler_vk_descriptor_selected(ir, k, Some(export))
}

fn compiler_vk_descriptor_selected(
    ir: &[u8],
    k: u32,
    export: Option<&str>,
) -> Result<Vec<u8>, CompilerBackendError> {
    let program = checked_program(ir, k, export)?;
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
    hash.update(program.export_digest);
    hash.update((pinned.len() as u64).to_le_bytes());
    hash.update(pinned.as_bytes());
    let mut descriptor = Vec::with_capacity(1 + 4 + 32 * 4);
    descriptor.push(2);
    descriptor.extend_from_slice(&k.to_le_bytes());
    descriptor.extend_from_slice(&program.profile_digest);
    descriptor.extend_from_slice(&program.ir_digest);
    descriptor.extend_from_slice(&program.export_digest);
    descriptor.extend_from_slice(&hash.finalize());
    Ok(descriptor)
}

fn checked_program(
    ir: &[u8],
    k: u32,
    export: Option<&str>,
) -> Result<CompilerProgram, CompilerBackendError> {
    if !(8..=20).contains(&k) {
        return Err(CompilerBackendError::LimitExceeded);
    }
    let program = CompilerProgram::decode_export(ir, export)?;
    if program.estimated_rows()? > (1usize << k) {
        return Err(CompilerBackendError::LimitExceeded);
    }
    Ok(program)
}

/// Creates a Halo2 proof for a canonical ONXIR program with exactly one export.
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
    create_compiler_proof_selected(ir, k, None, witness, public_inputs)
}

pub fn create_compiler_proof_for_export(
    ir: &[u8],
    k: u32,
    export: &str,
    witness: CompilerWitness,
    public_inputs: &[Fp],
) -> Result<Vec<u8>, CompilerBackendError> {
    create_compiler_proof_selected(ir, k, Some(export), witness, public_inputs)
}

fn create_compiler_proof_selected(
    ir: &[u8],
    k: u32,
    export: Option<&str>,
    witness: CompilerWitness,
    public_inputs: &[Fp],
) -> Result<Vec<u8>, CompilerBackendError> {
    let program = checked_program(ir, k, export)?;
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
        if let Some(bits) = parameter.kind.integer_bits() {
            let integer = canonical_u64(&witness.parameters[parameter_index])
                .ok_or(CompilerBackendError::InvalidWitness)?;
            if bits < 64 && integer >= (1u64 << bits) {
                return Err(CompilerBackendError::InvalidWitness);
            }
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

/// Verifies a single-export proof against the key derived solely from canonical IR and `k`.
pub fn verify_compiler_proof(
    ir: &[u8],
    k: u32,
    public_inputs: &[Fp],
    proof: &[u8],
) -> Result<(), CompilerBackendError> {
    verify_compiler_proof_selected(ir, k, None, public_inputs, proof)
}

pub fn verify_compiler_proof_for_export(
    ir: &[u8],
    k: u32,
    export: &str,
    public_inputs: &[Fp],
    proof: &[u8],
) -> Result<(), CompilerBackendError> {
    verify_compiler_proof_selected(ir, k, Some(export), public_inputs, proof)
}

fn verify_compiler_proof_selected(
    ir: &[u8],
    k: u32,
    export: Option<&str>,
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
    let program = checked_program(ir, k, export)?;
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
        instruction_with_guard(
            opcode,
            index,
            kind,
            operands,
            None,
            immediate,
            instruction_text,
        )
    }
    fn instruction_with_guard(
        opcode: u8,
        index: Option<usize>,
        kind: &str,
        operands: &[usize],
        guard: Option<usize>,
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
        out.extend(uleb(guard.map_or(0, |value| value as u64 + 1)));
        out.extend(uleb(immediate.map_or(0, |v| v + 1)));
        out.extend(text(instruction_text));
        out
    }

    fn guarded_division_ir() -> Vec<u8> {
        let mut ir = IR_DOMAIN.to_vec();
        ir.extend_from_slice(&[11u8; 32]);
        ir.push(1);
        ir.extend(text("guarded"));
        ir.push(1);
        ir.push(3);
        for (visibility, name, kind) in [
            (1u8, "left", "u8"),
            (2u8, "denominator", "u8"),
            (2u8, "condition", "bool"),
        ] {
            ir.push(visibility);
            ir.extend(text(name));
            ir.extend(text(kind));
        }
        ir.extend(text("u8"));
        ir.push(7);
        ir.extend(instruction(1, Some(0), "u8", &[], None, "public:left"));
        ir.extend(instruction(
            1,
            Some(1),
            "u8",
            &[],
            None,
            "private:denominator",
        ));
        ir.extend(instruction(
            1,
            Some(2),
            "bool",
            &[],
            None,
            "private:condition",
        ));
        ir.extend(instruction_with_guard(
            15,
            Some(3),
            "u8",
            &[0, 1],
            Some(2),
            None,
            "",
        ));
        ir.extend(instruction_with_guard(
            2,
            Some(4),
            "bool",
            &[],
            Some(2),
            Some(0),
            "",
        ));
        ir.extend(instruction_with_guard(
            26,
            None,
            "bool",
            &[4],
            Some(2),
            None,
            "",
        ));
        ir.extend(instruction(27, None, "u8", &[0], None, ""));
        ir
    }
    fn multiplication_ir() -> Vec<u8> {
        arithmetic_ir("field", 14)
    }

    fn arithmetic_ir(kind: &str, arithmetic_opcode: u8) -> Vec<u8> {
        let mut ir = IR_DOMAIN.to_vec();
        ir.extend_from_slice(&[7u8; 32]);
        ir.push(1);
        ir.extend(text("arithmetic"));
        ir.push(1);
        ir.push(2);
        for (visibility, name) in [(1u8, "left"), (2u8, "right")] {
            ir.push(visibility);
            ir.extend(text(name));
            ir.extend(text(kind));
        }
        ir.extend(text(kind));
        ir.push(4);
        ir.extend(instruction(1, Some(0), kind, &[], None, "public:left"));
        ir.extend(instruction(1, Some(1), kind, &[], None, "private:right"));
        ir.extend(instruction(
            arithmetic_opcode,
            Some(2),
            kind,
            &[0, 1],
            None,
            "",
        ));
        ir.extend(instruction(27, None, kind, &[2], None, ""));
        ir
    }

    fn comparison_ir(kind: &str, comparison_opcode: u8) -> Vec<u8> {
        let mut ir = IR_DOMAIN.to_vec();
        ir.extend_from_slice(&[9u8; 32]);
        ir.push(1);
        ir.extend(text("comparison"));
        ir.push(1);
        ir.push(2);
        for (visibility, name) in [(1u8, "left"), (2u8, "right")] {
            ir.push(visibility);
            ir.extend(text(name));
            ir.extend(text(kind));
        }
        ir.extend(text("bool"));
        ir.push(4);
        ir.extend(instruction(1, Some(0), kind, &[], None, "public:left"));
        ir.extend(instruction(1, Some(1), kind, &[], None, "private:right"));
        ir.extend(instruction(
            comparison_opcode,
            Some(2),
            "bool",
            &[0, 1],
            None,
            "",
        ));
        ir.extend(instruction(27, None, "bool", &[2], None, ""));
        ir
    }

    fn multiple_export_ir() -> Vec<u8> {
        let mut ir = IR_DOMAIN.to_vec();
        ir.extend_from_slice(&[13u8; 32]);
        ir.push(2);
        for name in ["alpha", "beta"] {
            ir.extend(text(name));
            ir.push(1);
            ir.push(2);
            for (visibility, parameter) in [(1u8, "left"), (2u8, "right")] {
                ir.push(visibility);
                ir.extend(text(parameter));
                ir.extend(text("field"));
            }
            ir.extend(text("field"));
            ir.push(4);
            ir.extend(instruction(1, Some(0), "field", &[], None, "public:left"));
            ir.extend(instruction(1, Some(1), "field", &[], None, "private:right"));
            ir.extend(instruction(12, Some(2), "field", &[0, 1], None, ""));
            ir.extend(instruction(27, None, "field", &[2], None, ""));
        }
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
    fn explicit_export_selection_binds_descriptors_and_proofs() {
        let ir = multiple_export_ir();
        assert!(matches!(
            CompilerProgram::decode(&ir),
            Err(CompilerBackendError::UnsupportedInstruction)
        ));
        let alpha = compiler_vk_descriptor_for_export(&ir, 8, "alpha").unwrap();
        let beta = compiler_vk_descriptor_for_export(&ir, 8, "beta").unwrap();
        assert_eq!(alpha.len(), 133);
        assert_ne!(alpha, beta);
        assert!(matches!(
            compiler_vk_descriptor_for_export(&ir, 8, "missing"),
            Err(CompilerBackendError::InvalidProgram)
        ));
        let public = [Fp::from(5), Fp::from(12)];
        let proof = create_compiler_proof_for_export(
            &ir,
            8,
            "alpha",
            CompilerWitness {
                parameters: vec![Fp::from(5), Fp::from(7)],
            },
            &public,
        )
        .unwrap();
        verify_compiler_proof_for_export(&ir, 8, "alpha", &public, &proof).unwrap();
        assert!(matches!(
            verify_compiler_proof_for_export(&ir, 8, "beta", &public, &proof),
            Err(CompilerBackendError::ProofVerification)
        ));
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
        let mut unsupported = multiplication_ir();
        let position = unsupported
            .windows(5)
            .position(|window| window == b"field")
            .unwrap();
        unsupported.splice(position..position + 5, b"u128".iter().copied());
        assert!(matches!(
            CompilerProgram::decode(&unsupported),
            Err(CompilerBackendError::UnsupportedType)
        ));
    }

    #[test]
    fn checked_unsigned_arithmetic_rejects_overflow_and_underflow() {
        for (opcode, left, right, expected) in
            [(12, 250, 5, 255), (13, 250, 5, 245), (14, 12, 20, 240)]
        {
            let ir = arithmetic_ir("u8", opcode);
            let program = CompilerProgram::decode(&ir).unwrap();
            let circuit = CompilerCircuit {
                program,
                witness: Some(CompilerWitness {
                    parameters: vec![Fp::from(left), Fp::from(right)],
                }),
            };
            MockProver::run(8, &circuit, vec![vec![Fp::from(left), Fp::from(expected)]])
                .unwrap()
                .assert_satisfied();
        }

        for (opcode, left, right) in [(12, 250, 6), (13, 5, 6), (14, 16, 16)] {
            let ir = arithmetic_ir("u8", opcode);
            let circuit = CompilerCircuit {
                program: CompilerProgram::decode(&ir).unwrap(),
                witness: Some(CompilerWitness {
                    parameters: vec![Fp::from(left), Fp::from(right)],
                }),
            };
            assert!(
                MockProver::run(8, &circuit, vec![vec![Fp::from(left), Fp::zero()]])
                    .unwrap()
                    .verify()
                    .is_err()
            );
        }

        let ir = arithmetic_ir("u8", 12);
        let public = [Fp::from(250), Fp::from(255)];
        let proof = create_compiler_proof(
            &ir,
            8,
            CompilerWitness {
                parameters: vec![Fp::from(250), Fp::from(5)],
            },
            &public,
        )
        .unwrap();
        verify_compiler_proof(&ir, 8, &public, &proof).unwrap();
    }

    #[test]
    fn unsigned_ordering_is_range_bound_at_equality_and_width_edges() {
        for (opcode, left, right, expected) in [
            (8, 0u64, 255u64, 1u64),
            (8, 255, 0, 0),
            (9, 17, 17, 1),
            (10, 17, 17, 0),
            (10, 255, 0, 1),
            (11, 0, 255, 0),
        ] {
            let ir = comparison_ir("u8", opcode);
            let circuit = CompilerCircuit {
                program: CompilerProgram::decode(&ir).unwrap(),
                witness: Some(CompilerWitness {
                    parameters: vec![Fp::from(left), Fp::from(right)],
                }),
            };
            MockProver::run(8, &circuit, vec![vec![Fp::from(left), Fp::from(expected)]])
                .unwrap()
                .assert_satisfied();
            assert!(MockProver::run(
                8,
                &circuit,
                vec![vec![Fp::from(left), Fp::from(1 - expected)]],
            )
            .unwrap()
            .verify()
            .is_err());
        }

        let ir = comparison_ir("u64", 9);
        let public = [Fp::from(u64::MAX), Fp::one()];
        let proof = create_compiler_proof(
            &ir,
            9,
            CompilerWitness {
                parameters: vec![Fp::from(u64::MAX), Fp::from(u64::MAX)],
            },
            &public,
        )
        .unwrap();
        verify_compiler_proof(&ir, 9, &public, &proof).unwrap();
    }

    #[test]
    fn integer_and_field_division_enforce_nonzero_euclidean_witnesses() {
        for (opcode, expected) in [(15, 35u64), (16, 5u64)] {
            let ir = arithmetic_ir("u8", opcode);
            let circuit = CompilerCircuit {
                program: CompilerProgram::decode(&ir).unwrap(),
                witness: Some(CompilerWitness {
                    parameters: vec![Fp::from(250), Fp::from(7)],
                }),
            };
            MockProver::run(8, &circuit, vec![vec![Fp::from(250), Fp::from(expected)]])
                .unwrap()
                .assert_satisfied();

            let zero_denominator = CompilerCircuit {
                program: CompilerProgram::decode(&ir).unwrap(),
                witness: Some(CompilerWitness {
                    parameters: vec![Fp::from(250), Fp::zero()],
                }),
            };
            assert!(
                MockProver::run(8, &zero_denominator, vec![vec![Fp::from(250), Fp::zero()]],)
                    .unwrap()
                    .verify()
                    .is_err()
            );
        }

        let field_ir = arithmetic_ir("field", 15);
        let field_circuit = CompilerCircuit {
            program: CompilerProgram::decode(&field_ir).unwrap(),
            witness: Some(CompilerWitness {
                parameters: vec![Fp::from(6), Fp::from(2)],
            }),
        };
        MockProver::run(8, &field_circuit, vec![vec![Fp::from(6), Fp::from(3)]])
            .unwrap()
            .assert_satisfied();

        let ir = arithmetic_ir("u8", 15);
        let public = [Fp::from(250), Fp::from(35)];
        let proof = create_compiler_proof(
            &ir,
            8,
            CompilerWitness {
                parameters: vec![Fp::from(250), Fp::from(7)],
            },
            &public,
        )
        .unwrap();
        verify_compiler_proof(&ir, 8, &public, &proof).unwrap();
    }

    #[test]
    fn dynamic_shifts_bind_counts_results_and_overflow() {
        for (opcode, left, count, expected) in
            [(17, 3u64, 2u64, 12u64), (18, 255, 4, 15), (18, 1, 0, 1)]
        {
            let ir = arithmetic_ir("u8", opcode);
            let circuit = CompilerCircuit {
                program: CompilerProgram::decode(&ir).unwrap(),
                witness: Some(CompilerWitness {
                    parameters: vec![Fp::from(left), Fp::from(count)],
                }),
            };
            MockProver::run(8, &circuit, vec![vec![Fp::from(left), Fp::from(expected)]])
                .unwrap()
                .assert_satisfied();
        }

        for (opcode, left, count) in [(17, 240u64, 1u64), (17, 1, 8), (18, 1, 8)] {
            let ir = arithmetic_ir("u8", opcode);
            let circuit = CompilerCircuit {
                program: CompilerProgram::decode(&ir).unwrap(),
                witness: Some(CompilerWitness {
                    parameters: vec![Fp::from(left), Fp::from(count)],
                }),
            };
            assert!(
                MockProver::run(8, &circuit, vec![vec![Fp::from(left), Fp::zero()]])
                    .unwrap()
                    .verify()
                    .is_err()
            );
        }

        let ir = arithmetic_ir("u64", 18);
        let public = [Fp::from(u64::MAX), Fp::from(0x00ff_ffff_ffff_ffff)];
        let proof = create_compiler_proof(
            &ir,
            10,
            CompilerWitness {
                parameters: vec![Fp::from(u64::MAX), Fp::from(8)],
            },
            &public,
        )
        .unwrap();
        verify_compiler_proof(&ir, 10, &public, &proof).unwrap();
    }

    #[test]
    fn guarded_execution_neutralizes_inactive_failures_but_enforces_active_ones() {
        let ir = guarded_division_ir();
        let inactive = CompilerCircuit {
            program: CompilerProgram::decode(&ir).unwrap(),
            witness: Some(CompilerWitness {
                parameters: vec![Fp::from(9), Fp::zero(), Fp::zero()],
            }),
        };
        MockProver::run(9, &inactive, vec![vec![Fp::from(9), Fp::from(9)]])
            .unwrap()
            .assert_satisfied();

        let active = CompilerCircuit {
            program: CompilerProgram::decode(&ir).unwrap(),
            witness: Some(CompilerWitness {
                parameters: vec![Fp::from(9), Fp::from(3), Fp::one()],
            }),
        };
        assert!(
            MockProver::run(9, &active, vec![vec![Fp::from(9), Fp::from(9)]])
                .unwrap()
                .verify()
                .is_err()
        );

        let public = [Fp::from(9), Fp::from(9)];
        let proof = create_compiler_proof(
            &ir,
            9,
            CompilerWitness {
                parameters: vec![Fp::from(9), Fp::zero(), Fp::zero()],
            },
            &public,
        )
        .unwrap();
        verify_compiler_proof(&ir, 9, &public, &proof).unwrap();
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
