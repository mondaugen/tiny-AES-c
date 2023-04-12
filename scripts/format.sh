#!/bin/bash
clang-format -style='{
    AlignAfterOpenBracket: Align,
    IndentWidth: 4,
    BinPackParameters: false,
    BreakBeforeBraces: Linux,
    AllowAllArgumentsOnNextLine: false,
    AllowAllParametersOfDeclarationOnNextLine: false,
    ReflowComments: true,
}' "$@"

