"""Three-valued, non-executable sink conditions over existing bounded evidence."""


def evaluate(conditions, registers, constants, trace):
    unknown = False
    for condition in conditions:
        if condition['kind'] == 'source_prefix':
            # External callback seeds are not a fully classified API source.
            if trace.source == 'external callback argument':
                unknown = True
            elif not trace.source.startswith(condition['prefix']):
                return 'NOT_MET'
        else:
            argument = condition['argument']
            if argument >= len(registers) or registers[argument] not in constants:
                unknown = True
                continue
            value = constants[registers[argument]]
            if condition['kind'] == 'argument_bits':
                if type(value) is not int or not -(2**31) <= value <= 0xffffffff:
                    unknown = True
                elif (value & condition['mask']) != condition['equals']:
                    return 'NOT_MET'
                continue
            if type(value) not in (str, int):
                unknown = True
            elif type(value) is not type(condition['equals']) or value != condition['equals']:
                return 'NOT_MET'
    return 'UNKNOWN' if unknown else 'MET'
