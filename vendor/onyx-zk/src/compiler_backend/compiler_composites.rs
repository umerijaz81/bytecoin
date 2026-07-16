use super::*;

const MAX_LAYOUT_LEAVES: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Layout {
    Scalar(ScalarType),
    Bytes(usize),
    Array(Box<Layout>, usize),
    Record(Vec<(String, Layout)>),
}

impl Layout {
    fn leaves(&self) -> Result<Vec<ScalarType>, CompilerBackendError> {
        let mut result = Vec::new();
        self.append_leaves(&mut result)?;
        Ok(result)
    }

    fn append_leaves(&self, output: &mut Vec<ScalarType>) -> Result<(), CompilerBackendError> {
        match self {
            Self::Scalar(kind) => output.push(*kind),
            Self::Bytes(length) => output.extend((0..*length).map(|_| ScalarType::Integer(8))),
            Self::Array(element, length) => {
                for _ in 0..*length {
                    element.append_leaves(output)?;
                    if output.len() > MAX_LAYOUT_LEAVES {
                        return Err(CompilerBackendError::LimitExceeded);
                    }
                }
            }
            Self::Record(fields) => {
                for (_, field) in fields {
                    field.append_leaves(output)?;
                }
            }
        }
        if output.len() > MAX_LAYOUT_LEAVES {
            Err(CompilerBackendError::LimitExceeded)
        } else {
            Ok(())
        }
    }

    fn scalar(&self) -> Option<ScalarType> {
        match self {
            Self::Scalar(kind) => Some(*kind),
            _ => None,
        }
    }
}

struct TypeParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TypeParser<'a> {
    fn parse(text: &'a str) -> Result<Layout, CompilerBackendError> {
        let mut parser = Self {
            bytes: text.as_bytes(),
            offset: 0,
        };
        let result = parser.layout()?;
        if parser.offset != parser.bytes.len() {
            return Err(CompilerBackendError::UnsupportedType);
        }
        result.leaves()?;
        Ok(result)
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.offset) == Some(&byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn number(&mut self, maximum: usize) -> Result<usize, CompilerBackendError> {
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset += 1;
        }
        let digits = &self.bytes[start..self.offset];
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return Err(CompilerBackendError::UnsupportedType);
        }
        let value = std::str::from_utf8(digits)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0 && *value <= maximum)
            .ok_or(CompilerBackendError::UnsupportedType)?;
        Ok(value)
    }

    fn name(&mut self) -> Result<String, CompilerBackendError> {
        let start = self.offset;
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.offset += 1;
        }
        let value = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| CompilerBackendError::UnsupportedType)?;
        if !identifier(value) {
            return Err(CompilerBackendError::UnsupportedType);
        }
        Ok(value.to_owned())
    }

    fn layout(&mut self) -> Result<Layout, CompilerBackendError> {
        let remaining = &self.bytes[self.offset..];
        for (text, kind) in [
            (b"bool".as_slice(), ScalarType::Bool),
            (b"u8".as_slice(), ScalarType::Integer(8)),
            (b"u16".as_slice(), ScalarType::Integer(16)),
            (b"u32".as_slice(), ScalarType::Integer(32)),
            (b"u64".as_slice(), ScalarType::Integer(64)),
            (b"field".as_slice(), ScalarType::Field),
        ] {
            if remaining.starts_with(text) {
                self.offset += text.len();
                return Ok(Layout::Scalar(kind));
            }
        }
        if remaining.starts_with(b"bytes<") {
            self.offset += 6;
            let length = self.number(4096)?;
            if !self.consume(b'>') {
                return Err(CompilerBackendError::UnsupportedType);
            }
            return Ok(Layout::Bytes(length));
        }
        if self.consume(b'[') {
            let element = self.layout()?;
            if !self.consume(b';') {
                return Err(CompilerBackendError::UnsupportedType);
            }
            let length = self.number(1024)?;
            if !self.consume(b']') {
                return Err(CompilerBackendError::UnsupportedType);
            }
            return Ok(Layout::Array(Box::new(element), length));
        }
        if self.consume(b'{') {
            let mut fields = Vec::new();
            loop {
                let name = self.name()?;
                if !self.consume(b':') {
                    return Err(CompilerBackendError::UnsupportedType);
                }
                let field = self.layout()?;
                if fields.last().is_some_and(|(previous, _)| previous >= &name) {
                    return Err(CompilerBackendError::UnsupportedType);
                }
                fields.push((name, field));
                if self.consume(b'}') {
                    break;
                }
                if !self.consume(b',') {
                    return Err(CompilerBackendError::UnsupportedType);
                }
            }
            return Ok(Layout::Record(fields));
        }
        Err(CompilerBackendError::UnsupportedType)
    }
}

#[derive(Clone)]
struct RawParameter {
    visibility: Visibility,
    name: String,
    kind: Layout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawOpcode {
    Scalar(Opcode),
    Bytes,
    Array,
    Index,
    Record,
    Field,
}

#[derive(Clone)]
struct RawInstruction {
    opcode: RawOpcode,
    result: Option<usize>,
    kind: Layout,
    operands: Vec<usize>,
    guard: Option<usize>,
    immediate: Option<u64>,
    text: String,
}

#[derive(Clone)]
struct RawFunction {
    name: String,
    exported: bool,
    parameters: Vec<RawParameter>,
    return_type: Layout,
    instructions: Vec<RawInstruction>,
}

fn raw_opcode(value: u8) -> Result<RawOpcode, CompilerBackendError> {
    match value {
        19 => Ok(RawOpcode::Bytes),
        20 => Ok(RawOpcode::Array),
        21 => Ok(RawOpcode::Index),
        22 => Ok(RawOpcode::Record),
        23 => Ok(RawOpcode::Field),
        value => opcode(value).map(RawOpcode::Scalar),
    }
}

fn parse_raw(ir: &[u8]) -> Result<([u8; 32], Vec<RawFunction>), CompilerBackendError> {
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
    let profile_digest = reader
        .take(32)?
        .try_into()
        .map_err(|_| CompilerBackendError::InvalidEncoding)?;
    let count = usize::try_from(reader.uleb()?).map_err(|_| CompilerBackendError::LimitExceeded)?;
    if count == 0 || count > MAX_FUNCTIONS {
        return Err(CompilerBackendError::LimitExceeded);
    }
    let mut functions = Vec::with_capacity(count);
    let mut signatures = BTreeMap::<String, (Vec<Layout>, Layout)>::new();
    for _ in 0..count {
        let name = reader.text(128)?;
        if !identifier(&name) || signatures.contains_key(&name) {
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
            parameters.push(RawParameter {
                visibility,
                name: parameter_name,
                kind: TypeParser::parse(&reader.text(8192)?)?,
            });
        }
        let return_type = TypeParser::parse(&reader.text(8192)?)?;
        let instruction_count =
            usize::try_from(reader.uleb()?).map_err(|_| CompilerBackendError::LimitExceeded)?;
        if instruction_count == 0 || instruction_count > MAX_INSTRUCTIONS {
            return Err(CompilerBackendError::LimitExceeded);
        }
        let mut instructions = Vec::with_capacity(instruction_count);
        for index in 0..instruction_count {
            let opcode = raw_opcode(reader.byte()?)?;
            let encoded_result = reader.uleb()?;
            let result = (encoded_result != 0)
                .then(|| {
                    usize::try_from(encoded_result - 1)
                        .map_err(|_| CompilerBackendError::LimitExceeded)
                })
                .transpose()?;
            let kind = TypeParser::parse(&reader.text(8192)?)?;
            let operand_count =
                usize::try_from(reader.uleb()?).map_err(|_| CompilerBackendError::LimitExceeded)?;
            if operand_count > 4096 {
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
            let guard = (encoded_guard != 0)
                .then(|| {
                    usize::try_from(encoded_guard - 1)
                        .map_err(|_| CompilerBackendError::LimitExceeded)
                })
                .transpose()?;
            if guard.is_some_and(|guard| guard >= index) {
                return Err(CompilerBackendError::InvalidProgram);
            }
            let encoded_immediate = reader.uleb()?;
            let immediate = if encoded_immediate == 0 {
                None
            } else {
                Some(encoded_immediate - 1)
            };
            let text = reader.text(8192)?;
            let side_effect = matches!(opcode, RawOpcode::Scalar(Opcode::Assert | Opcode::Return));
            if side_effect != result.is_none() || result.is_some_and(|result| result != index) {
                return Err(CompilerBackendError::InvalidProgram);
            }
            instructions.push(RawInstruction {
                opcode,
                result,
                kind,
                operands,
                guard,
                immediate,
                text,
            });
        }
        validate_raw(&parameters, &return_type, &instructions, &signatures)?;
        signatures.insert(
            name.clone(),
            (
                parameters
                    .iter()
                    .map(|parameter| parameter.kind.clone())
                    .collect(),
                return_type.clone(),
            ),
        );
        functions.push(RawFunction {
            name,
            exported,
            parameters,
            return_type,
            instructions,
        });
    }
    if reader.offset != ir.len() {
        return Err(CompilerBackendError::InvalidEncoding);
    }
    Ok((profile_digest, functions))
}

fn validate_raw(
    parameters: &[RawParameter],
    return_type: &Layout,
    instructions: &[RawInstruction],
    signatures: &BTreeMap<String, (Vec<Layout>, Layout)>,
) -> Result<(), CompilerBackendError> {
    let mut types = Vec::<Option<Layout>>::with_capacity(instructions.len());
    let mut parameter_index = 0usize;
    let mut returns = 0usize;
    for (index, instruction) in instructions.iter().enumerate() {
        if instruction.guard.is_some_and(|guard| {
            types.get(guard).and_then(Option::as_ref) != Some(&Layout::Scalar(ScalarType::Bool))
        }) || matches!(
            instruction.opcode,
            RawOpcode::Scalar(Opcode::Parameter | Opcode::Return)
        ) && instruction.guard.is_some()
        {
            return Err(CompilerBackendError::InvalidProgram);
        }
        let operand_types: Vec<_> = instruction
            .operands
            .iter()
            .map(|operand| {
                types[*operand]
                    .clone()
                    .ok_or(CompilerBackendError::InvalidProgram)
            })
            .collect::<Result<_, _>>()?;
        match instruction.opcode {
            RawOpcode::Scalar(Opcode::Parameter) => {
                let parameter = parameters
                    .get(parameter_index)
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                let prefix = if parameter.visibility == Visibility::Public {
                    "public:"
                } else {
                    "private:"
                };
                if index != parameter_index
                    || instruction.kind != parameter.kind
                    || !instruction.operands.is_empty()
                    || instruction.guard.is_some()
                    || instruction.immediate.is_some()
                    || instruction.text != prefix.to_owned() + &parameter.name
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
                parameter_index += 1;
            }
            RawOpcode::Scalar(Opcode::Constant) => {
                let kind = instruction
                    .kind
                    .scalar()
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                let immediate = instruction
                    .immediate
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                if !instruction.operands.is_empty()
                    || !instruction.text.is_empty()
                    || kind == ScalarType::Bool && immediate > 1
                    || kind
                        .integer_bits()
                        .is_some_and(|bits| bits < 64 && immediate >= (1u64 << bits))
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            RawOpcode::Bytes => {
                let Layout::Bytes(length) = instruction.kind else {
                    return Err(CompilerBackendError::InvalidProgram);
                };
                if !instruction.operands.is_empty()
                    || instruction.immediate.is_some()
                    || instruction.text.len() != length * 2
                    || !instruction
                        .text
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            RawOpcode::Array => {
                let Layout::Array(ref element, length) = instruction.kind else {
                    return Err(CompilerBackendError::InvalidProgram);
                };
                if operand_types.len() != length
                    || operand_types.iter().any(|kind| kind != element.as_ref())
                    || instruction.immediate.is_some()
                    || !instruction.text.is_empty()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            RawOpcode::Record => {
                let Layout::Record(ref fields) = instruction.kind else {
                    return Err(CompilerBackendError::InvalidProgram);
                };
                if operand_types
                    != fields
                        .iter()
                        .map(|(_, kind)| kind.clone())
                        .collect::<Vec<_>>()
                    || instruction.immediate.is_some()
                    || !instruction.text.is_empty()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            RawOpcode::Field => {
                let [record] = operand_types.as_slice() else {
                    return Err(CompilerBackendError::InvalidProgram);
                };
                let Layout::Record(fields) = record else {
                    return Err(CompilerBackendError::InvalidProgram);
                };
                let field = instruction
                    .immediate
                    .and_then(|index| fields.get(index as usize))
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                if instruction.kind != field.1 || !instruction.text.is_empty() {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            RawOpcode::Index => {
                let [array, index] = operand_types.as_slice() else {
                    return Err(CompilerBackendError::InvalidProgram);
                };
                let Layout::Array(element, length) = array else {
                    return Err(CompilerBackendError::InvalidProgram);
                };
                if index != &Layout::Scalar(ScalarType::Integer(64))
                    || instruction.kind != **element
                    || instruction.immediate != Some(*length as u64)
                    || !instruction.text.is_empty()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            RawOpcode::Scalar(Opcode::Call) => {
                let (expected, result) = signatures
                    .get(&instruction.text)
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                if &operand_types != expected
                    || &instruction.kind != result
                    || instruction.immediate.is_some()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            RawOpcode::Scalar(Opcode::Intrinsic) => {
                let expected = match instruction.text.as_str() {
                    "poseidon_hash" | "merkle_root" => 2,
                    "nullifier" => 3,
                    _ => return Err(CompilerBackendError::InvalidProgram),
                };
                if operand_types != vec![Layout::Scalar(ScalarType::Field); expected]
                    || instruction.kind != Layout::Scalar(ScalarType::Field)
                    || instruction.immediate.is_some()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
            RawOpcode::Scalar(Opcode::Return) => {
                if operand_types != [return_type.clone()]
                    || &instruction.kind != return_type
                    || instruction.immediate.is_some()
                    || !instruction.text.is_empty()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
                returns += 1;
            }
            RawOpcode::Scalar(opcode) => {
                let scalar_kind = instruction
                    .kind
                    .scalar()
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                let scalar_operands: Vec<_> = operand_types.iter().map(Layout::scalar).collect();
                if scalar_operands.iter().any(Option::is_none)
                    || !instruction.text.is_empty()
                    || instruction.immediate.is_some()
                {
                    return Err(CompilerBackendError::InvalidProgram);
                }
                let actual: Vec<_> = scalar_operands.into_iter().flatten().collect();
                let valid = match opcode {
                    Opcode::Not => actual == [ScalarType::Bool] && scalar_kind == ScalarType::Bool,
                    Opcode::And | Opcode::Or => {
                        actual == [ScalarType::Bool, ScalarType::Bool]
                            && scalar_kind == ScalarType::Bool
                    }
                    Opcode::Equal | Opcode::NotEqual => {
                        actual.len() == 2
                            && actual[0] == actual[1]
                            && scalar_kind == ScalarType::Bool
                    }
                    Opcode::Less | Opcode::LessEqual | Opcode::Greater | Opcode::GreaterEqual => {
                        actual.len() == 2
                            && actual[0] == actual[1]
                            && actual[0].integer_bits().is_some()
                            && scalar_kind == ScalarType::Bool
                    }
                    Opcode::Add | Opcode::Subtract | Opcode::Multiply | Opcode::Divide => {
                        actual == [scalar_kind, scalar_kind]
                            && (scalar_kind == ScalarType::Field
                                || scalar_kind.integer_bits().is_some())
                    }
                    Opcode::Remainder | Opcode::ShiftLeft | Opcode::ShiftRight => {
                        actual == [scalar_kind, scalar_kind] && scalar_kind.integer_bits().is_some()
                    }
                    Opcode::Assert => {
                        actual == [ScalarType::Bool] && scalar_kind == ScalarType::Bool
                    }
                    Opcode::Select => actual == [ScalarType::Bool, scalar_kind, scalar_kind],
                    _ => false,
                };
                if !valid {
                    return Err(CompilerBackendError::InvalidProgram);
                }
            }
        }
        types.push(instruction.result.map(|_| instruction.kind.clone()));
    }
    if parameter_index != parameters.len()
        || returns != 1
        || !matches!(
            instructions.last().map(|instruction| instruction.opcode),
            Some(RawOpcode::Scalar(Opcode::Return))
        )
    {
        return Err(CompilerBackendError::InvalidProgram);
    }
    Ok(())
}

fn emit(
    output: &mut Vec<Instruction>,
    opcode: Opcode,
    kind: ScalarType,
    operands: Vec<usize>,
    guard: Option<usize>,
    immediate: Option<u64>,
) -> Result<usize, CompilerBackendError> {
    if output.len() >= MAX_INSTRUCTIONS {
        return Err(CompilerBackendError::LimitExceeded);
    }
    let result = output.len();
    output.push(Instruction {
        opcode,
        result: Some(result),
        kind,
        operands,
        guard,
        immediate,
        text: String::new(),
    });
    Ok(result)
}

fn emit_zero(
    output: &mut Vec<Instruction>,
    kind: ScalarType,
) -> Result<usize, CompilerBackendError> {
    emit(output, Opcode::Constant, kind, Vec::new(), None, Some(0))
}

fn neutralize(
    output: &mut Vec<Instruction>,
    guard: Option<usize>,
    values: Vec<usize>,
) -> Result<Vec<usize>, CompilerBackendError> {
    let Some(guard) = guard else {
        return Ok(values);
    };
    values
        .into_iter()
        .map(|value| {
            let kind = output[value].kind;
            let zero = emit_zero(output, kind)?;
            emit(
                output,
                Opcode::Select,
                kind,
                vec![guard, value, zero],
                None,
                None,
            )
        })
        .collect()
}

fn flatten(
    functions: &[RawFunction],
    function_index: usize,
    arguments: Option<&[Vec<usize>]>,
    inherited_guard: Option<usize>,
    output: &mut Vec<Instruction>,
    parameters: &mut Vec<Parameter>,
) -> Result<Vec<usize>, CompilerBackendError> {
    let function = &functions[function_index];
    if arguments.is_some_and(|arguments| arguments.len() != function.parameters.len()) {
        return Err(CompilerBackendError::InvalidProgram);
    }
    let mut mapping = vec![Vec::<usize>::new(); function.instructions.len()];
    let mut parameter_index = 0usize;
    for (old_index, instruction) in function.instructions.iter().enumerate() {
        if instruction.opcode == RawOpcode::Scalar(Opcode::Parameter) {
            if let Some(arguments) = arguments {
                mapping[old_index] = arguments[parameter_index].clone();
            } else {
                let parameter = &function.parameters[parameter_index];
                let leaves = parameter.kind.leaves()?;
                let multiple = leaves.len() > 1;
                for (leaf_index, kind) in leaves.into_iter().enumerate() {
                    let name = if multiple {
                        format!("{}__{leaf_index}", parameter.name)
                    } else {
                        parameter.name.clone()
                    };
                    let result = output.len();
                    parameters.push(Parameter {
                        visibility: parameter.visibility,
                        name: name.clone(),
                        kind,
                    });
                    output.push(Instruction {
                        opcode: Opcode::Parameter,
                        result: Some(result),
                        kind,
                        operands: Vec::new(),
                        guard: None,
                        immediate: None,
                        text: format!(
                            "{}:{name}",
                            if parameter.visibility == Visibility::Public {
                                "public"
                            } else {
                                "private"
                            }
                        ),
                    });
                    mapping[old_index].push(result);
                }
            }
            parameter_index += 1;
            continue;
        }
        let operands: Vec<Vec<usize>> = instruction
            .operands
            .iter()
            .map(|operand| mapping[*operand].clone())
            .collect();
        let own_guard = instruction.guard.map(|guard| mapping[guard][0]);
        let guard = match (inherited_guard, own_guard) {
            (Some(left), Some(right)) => Some(emit(
                output,
                Opcode::And,
                ScalarType::Bool,
                vec![left, right],
                None,
                None,
            )?),
            (left, right) => left.or(right),
        };
        let values = match instruction.opcode {
            RawOpcode::Scalar(Opcode::Call) => {
                let target = functions[..function_index]
                    .iter()
                    .position(|candidate| candidate.name == instruction.text)
                    .ok_or(CompilerBackendError::InvalidProgram)?;
                flatten(
                    functions,
                    target,
                    Some(&operands),
                    guard,
                    output,
                    parameters,
                )?
            }
            RawOpcode::Scalar(Opcode::Return) => {
                let values = operands[0].clone();
                return neutralize(output, inherited_guard, values);
            }
            RawOpcode::Bytes => {
                let mut values = Vec::with_capacity(instruction.text.len() / 2);
                for pair in instruction.text.as_bytes().chunks_exact(2) {
                    let byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                        .map_err(|_| CompilerBackendError::InvalidProgram)?;
                    values.push(emit(
                        output,
                        Opcode::Constant,
                        ScalarType::Integer(8),
                        Vec::new(),
                        guard,
                        Some(u64::from(byte)),
                    )?);
                }
                values
            }
            RawOpcode::Array | RawOpcode::Record => {
                neutralize(output, guard, operands.into_iter().flatten().collect())?
            }
            RawOpcode::Field => {
                let Layout::Record(fields) = &function.instructions[instruction.operands[0]].kind
                else {
                    unreachable!()
                };
                let field_index = instruction.immediate.unwrap() as usize;
                let start: usize = fields[..field_index]
                    .iter()
                    .map(|(_, field)| field.leaves().unwrap().len())
                    .sum();
                let length = fields[field_index].1.leaves()?.len();
                neutralize(output, guard, operands[0][start..start + length].to_vec())?
            }
            RawOpcode::Index => {
                let Layout::Array(element, length) =
                    &function.instructions[instruction.operands[0]].kind
                else {
                    unreachable!()
                };
                let index = operands[1][0];
                let bound = emit(
                    output,
                    Opcode::Constant,
                    ScalarType::Integer(64),
                    Vec::new(),
                    guard,
                    Some(*length as u64),
                )?;
                let in_range = emit(
                    output,
                    Opcode::Less,
                    ScalarType::Bool,
                    vec![index, bound],
                    guard,
                    None,
                )?;
                output.push(Instruction {
                    opcode: Opcode::Assert,
                    result: None,
                    kind: ScalarType::Bool,
                    operands: vec![in_range],
                    guard,
                    immediate: None,
                    text: String::new(),
                });
                let leaf_kinds = element.leaves()?;
                let mut result = Vec::with_capacity(leaf_kinds.len());
                for (leaf, kind) in leaf_kinds.into_iter().enumerate() {
                    let mut selected = emit_zero(output, kind)?;
                    for item in 0..*length {
                        let item_constant = emit(
                            output,
                            Opcode::Constant,
                            ScalarType::Integer(64),
                            Vec::new(),
                            guard,
                            Some(item as u64),
                        )?;
                        let matches = emit(
                            output,
                            Opcode::Equal,
                            ScalarType::Bool,
                            vec![index, item_constant],
                            guard,
                            None,
                        )?;
                        selected = emit(
                            output,
                            Opcode::Select,
                            kind,
                            vec![
                                matches,
                                operands[0][item * element.leaves()?.len() + leaf],
                                selected,
                            ],
                            None,
                            None,
                        )?;
                    }
                    result.push(selected);
                }
                result
            }
            RawOpcode::Scalar(Opcode::Assert) => {
                output.push(Instruction {
                    opcode: Opcode::Assert,
                    result: None,
                    kind: ScalarType::Bool,
                    operands: vec![operands[0][0]],
                    guard,
                    immediate: None,
                    text: String::new(),
                });
                Vec::new()
            }
            RawOpcode::Scalar(opcode) => {
                let kind = instruction.kind.scalar().unwrap();
                let result = emit(
                    output,
                    opcode,
                    kind,
                    operands.into_iter().map(|operand| operand[0]).collect(),
                    guard,
                    instruction.immediate,
                )?;
                if opcode == Opcode::Intrinsic {
                    output[result].text = instruction.text.clone();
                }
                vec![result]
            }
        };
        if instruction.result.is_some() {
            mapping[old_index] = values;
        }
    }
    Err(CompilerBackendError::InvalidProgram)
}

pub(super) fn decode_composite_program(ir: &[u8]) -> Result<CompilerProgram, CompilerBackendError> {
    let (profile_digest, functions) = parse_raw(ir)?;
    let exports: Vec<_> = functions
        .iter()
        .enumerate()
        .filter(|(_, function)| function.exported)
        .map(|(index, _)| index)
        .collect();
    if exports.len() != 1 {
        return Err(CompilerBackendError::UnsupportedInstruction);
    }
    let export = &functions[exports[0]];
    let mut instructions = Vec::new();
    let mut parameters = Vec::new();
    let returned = flatten(
        &functions,
        exports[0],
        None,
        None,
        &mut instructions,
        &mut parameters,
    )?;
    let return_types = export.return_type.leaves()?;
    if returned.len() != return_types.len() {
        return Err(CompilerBackendError::InvalidProgram);
    }
    for (value, kind) in returned.into_iter().zip(return_types.iter().copied()) {
        instructions.push(Instruction {
            opcode: Opcode::Return,
            result: None,
            kind,
            operands: vec![value],
            guard: None,
            immediate: None,
            text: String::new(),
        });
    }
    let function = lower_guards(Function {
        name: export.name.clone(),
        exported: true,
        parameters,
        return_types,
        instructions,
    })?;
    Ok(CompilerProgram {
        profile_digest,
        ir_digest: Sha256::digest(ir).into(),
        function,
    })
}
