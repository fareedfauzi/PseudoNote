# -*- coding: utf-8 -*-
"""
Syntax highlighting for code editors (MultiHighlighter).
"""

from pseudonote.qt_compat import QtWidgets, QtCore, QtGui

MultiHighlighter = None

if QtWidgets:
    class MultiHighlighter(QtGui.QSyntaxHighlighter):
        def __init__(self, document):
            super().__init__(document)
            self.rules = []
            self.comment_start = QtCore.QRegExp(r'/\*')
            self.comment_end = QtCore.QRegExp(r'\*/')
            self.multiline_comment_format = QtGui.QTextCharFormat()
            self.multiline_comment_format.setForeground(QtGui.QColor("#6A9955"))

            self.update_rules("C")

        def update_rules(self, lang):
            self.rules = []
            keywords = []
            types = []


            k_fmt = QtGui.QTextCharFormat()
            k_fmt.setForeground(QtGui.QColor("#569CD6"))
            k_fmt.setFontWeight(QtGui.QFont.Bold)

            t_fmt = QtGui.QTextCharFormat()
            t_fmt.setForeground(QtGui.QColor("#4EC9B0"))
            t_fmt.setFontWeight(QtGui.QFont.Bold)

            f_fmt = QtGui.QTextCharFormat()
            f_fmt.setForeground(QtGui.QColor("#DCDCAA"))

            s_fmt = QtGui.QTextCharFormat()
            s_fmt.setForeground(QtGui.QColor("#CE9178"))

            c_fmt = QtGui.QTextCharFormat()
            c_fmt.setForeground(QtGui.QColor("#6A9955"))

            n_fmt = QtGui.QTextCharFormat()
            n_fmt.setForeground(QtGui.QColor("#B5CEA8"))

            if lang in ["C", "C++"]:
                keywords = [
                    'alignas', 'alignof', 'and', 'and_eq', 'asm', 'auto', 'bitand',
                    'bitor', 'bool', 'break', 'case', 'catch', 'char', 'char16_t',
                    'char32_t', 'class', 'compl', 'const', 'constexpr', 'const_cast',
                    'continue', 'decltype', 'default', 'delete', 'do', 'double',
                    'dynamic_cast', 'else', 'enum', 'explicit', 'export', 'extern',
                    'false', 'float', 'for', 'friend', 'goto', 'if', 'inline', 'int',
                    'long', 'mutable', 'namespace', 'new', 'noexcept', 'not', 'not_eq',
                    'nullptr', 'operator', 'or', 'or_eq', 'private', 'protected',
                    'public', 'register', 'reinterpret_cast', 'return', 'short',
                    'signed', 'sizeof', 'static', 'static_assert', 'static_cast',
                    'struct', 'switch', 'template', 'this', 'thread_local', 'throw',
                    'true', 'try', 'typedef', 'typeid', 'typename', 'union',
                    'unsigned', 'using', 'virtual', 'void', 'volatile', 'wchar_t',
                    'while', 'xor', 'xor_eq'
                ]
                types = [
                    'DWORD', 'HANDLE', 'LPVOID', 'LPCVOID', 'size_t', 'uintptr_t',
                    'int32_t', 'uint32_t', 'int64_t', 'uint64_t', 'BOOL', 'BYTE',
                    'WORD', 'FLOAT', 'PVOID', 'PSTR', 'PWSTR', 'LPSTR', 'LPWSTR',
                    'LPCSTR', 'LPCWSTR', 'HMODULE', 'HWND', 'HINSTANCE', 'FARPROC',
                    'UCHAR', 'USHORT', 'UINT', 'ULONG', 'LONGLONG', 'ULONGLONG',
                    '__int8', '__int16', '__int32', '__int64', '__stdcall', '__cdecl',
                    'WINAPI', 'APIENTRY'
                ]
                self.rules.append((QtCore.QRegExp(r'\b[A-Za-z0-9_]+(?=\()'), f_fmt))
                self.rules.append((QtCore.QRegExp(r'#[^\n]*'), k_fmt))
                self.rules.append((QtCore.QRegExp(r'//[^\n]*'), c_fmt))
                self.comment_start = QtCore.QRegExp(r'/\*')
                self.comment_end = QtCore.QRegExp(r'\*/')

            elif lang == "Go":
                keywords = [
                    'break', 'case', 'chan', 'const', 'continue', 'default', 'defer',
                    'else', 'fallthrough', 'for', 'func', 'go', 'goto', 'if', 'import',
                    'interface', 'map', 'package', 'range', 'return', 'select', 'struct',
                    'switch', 'type', 'var'
                ]
                types = [
                    'bool', 'byte', 'complex64', 'complex128', 'error', 'float32', 'float64',
                    'int', 'int8', 'int16', 'int32', 'int64', 'rune', 'string',
                    'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'uintptr', 'true', 'false', 'iota', 'nil'
                ]
                self.rules.append((QtCore.QRegExp(r'\bfunc\s+([A-Za-z0-9_]+)'), f_fmt))
                self.rules.append((QtCore.QRegExp(r'//[^\n]*'), c_fmt))
                self.comment_start = QtCore.QRegExp(r'/\*')
                self.comment_end = QtCore.QRegExp(r'\*/')

            elif lang == "Rust":
                keywords = [
                    'as', 'async', 'await', 'break', 'const', 'continue', 'crate', 'dyn', 'else',
                    'enum', 'extern', 'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop',
                    'match', 'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self',
                    'static', 'struct', 'super', 'trait', 'true', 'type', 'union', 'unsafe',
                    'use', 'where', 'while'
                ]
                types = [
                    'bool', 'char', 'f32', 'f64', 'i8', 'i16', 'i32', 'i64', 'i128', 'isize',
                    'u8', 'u16', 'u32', 'u64', 'u128', 'usize', 'str', 'String', 'Vec', 'Option', 'Result'
                ]
                self.rules.append((QtCore.QRegExp(r'\bfn\s+([A-Za-z0-9_]+)'), f_fmt))
                self.rules.append((QtCore.QRegExp(r'\b[A-Za-z0-9_]+(?=\!)'), f_fmt))
                self.rules.append((QtCore.QRegExp(r'//[^\n]*'), c_fmt))
                self.comment_start = QtCore.QRegExp(r'/\*')
                self.comment_end = QtCore.QRegExp(r'\*/')

            elif lang == "Delphi":
                keywords = [
                    'and', 'array', 'as', 'asm', 'begin', 'case', 'class', 'const', 'constructor',
                    'destructor', 'dispinterface', 'div', 'do', 'downto', 'else', 'end', 'except',
                    'exports', 'file', 'finalization', 'finally', 'for', 'function', 'goto', 'if',
                    'implementation', 'in', 'inherited', 'initialization', 'inline', 'interface',
                    'is', 'label', 'library', 'mod', 'nil', 'not', 'object', 'of', 'or', 'out',
                    'packed', 'procedure', 'program', 'property', 'raise', 'record', 'repeat',
                    'resourcestring', 'set', 'shl', 'shr', 'string', 'then', 'threadvar', 'to',
                    'try', 'type', 'unit', 'until', 'uses', 'var', 'while', 'with', 'xor'
                ]
                types = [
                    'Integer', 'Cardinal', 'ShortInt', 'SmallInt', 'LongInt', 'Int64', 'Byte', 'Word',
                    'LongWord', 'UInt64', 'Boolean', 'ByteBool', 'WordBool', 'LongBool', 'Char', 'AnsiChar',
                    'WideChar', 'Real', 'Single', 'Double', 'Extended', 'Comp', 'Currency', 'Pointer', 'TObject'
                ]
                self.rules.append((QtCore.QRegExp(r'//[^\n]*'), c_fmt))
                self.rules.append((QtCore.QRegExp(r'\{[^}]*\}'), c_fmt))
                self.comment_start = QtCore.QRegExp(r'\(*')
                self.comment_end = QtCore.QRegExp(r'*\)')

            elif lang == "Nim":
                keywords = [
                    'addr', 'and', 'as', 'asm', 'bind', 'block', 'break', 'case', 'cast',
                    'concept', 'const', 'continue', 'converter', 'defer', 'discard', 'distinct',
                    'div', 'do', 'elif', 'else', 'end', 'enum', 'except', 'export', 'finally',
                    'for', 'from', 'func', 'if', 'import', 'in', 'include', 'interface', 'is',
                    'isnot', 'iterator', 'let', 'macro', 'method', 'mixin', 'mod', 'nil', 'not',
                    'notin', 'object', 'of', 'or', 'out', 'proc', 'ptr', 'raise', 'ref', 'return',
                    'shl', 'shr', 'static', 'template', 'try', 'tuple', 'type', 'using', 'var',
                    'when', 'while', 'xor', 'yield'
                ]
                types = ['int', 'int8', 'int16', 'int32', 'int64', 'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'float', 'float32', 'float64', 'string', 'char', 'bool']
                self.rules.append((QtCore.QRegExp(r'\bproc\s+([A-Za-z0-9_]+)'), f_fmt))
                self.rules.append((QtCore.QRegExp(r'#[^\n]*'), c_fmt))
                self.comment_start = QtCore.QRegExp(r'#\[')
                self.comment_end = QtCore.QRegExp(r']#')

            elif lang == "Python":
                keywords = [
                    'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break',
                    'class', 'continue', 'def', 'del', 'elif', 'else', 'except', 'finally',
                    'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda', 'nonlocal',
                    'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield'
                ]
                types = [
                    'bool', 'int', 'float', 'complex', 'str', 'bytes', 'bytearray', 'list',
                    'tuple', 'dict', 'set', 'frozenset', 'range', 'object'
                ]
                self.rules.append((QtCore.QRegExp(r'\bdef\s+([A-Za-z0-9_]+)'), f_fmt))
                self.rules.append((QtCore.QRegExp(r'\bclass\s+([A-Za-z0-9_]+)'), f_fmt))
                self.rules.append((QtCore.QRegExp(r'#[^\n]*'), c_fmt))

                self.comment_start = QtCore.QRegExp(r'\"\"\"')
                self.comment_end = QtCore.QRegExp(r'\"\"\"')


            elif lang == "C#":
                keywords = [
                    'abstract', 'as', 'base', 'bool', 'break', 'byte', 'case', 'catch', 'char',
                    'checked', 'class', 'const', 'continue', 'decimal', 'default', 'delegate', 'do',
                    'double', 'else', 'enum', 'event', 'explicit', 'extern', 'false', 'finally',
                    'fixed', 'float', 'for', 'foreach', 'goto', 'if', 'implicit', 'in', 'int',
                    'interface', 'internal', 'is', 'lock', 'long', 'namespace', 'new', 'null',
                    'object', 'operator', 'out', 'override', 'params', 'private', 'protected',
                    'public', 'readonly', 'ref', 'return', 'sbyte', 'sealed', 'short', 'sizeof',
                    'stackalloc', 'static', 'string', 'struct', 'switch', 'this', 'throw', 'true',
                    'try', 'typeof', 'uint', 'ulong', 'unchecked', 'unsafe', 'ushort', 'using',
                    'virtual', 'void', 'volatile', 'while', 'var', 'async', 'await', 'dynamic'
                ]
                types = [
                    'Boolean', 'Byte', 'SByte', 'Int16', 'UInt16', 'Int32', 'UInt32', 'Int64', 'UInt64',
                    'IntPtr', 'UIntPtr', 'Char', 'Double', 'Single', 'Decimal', 'String', 'Object', 'List', 'Dictionary'
                ]
                self.rules.append((QtCore.QRegExp(r'\b[A-Za-z0-9_]+(?=\()'), f_fmt))
                self.rules.append((QtCore.QRegExp(r'//[^\n]*'), c_fmt))
                self.comment_start = QtCore.QRegExp(r'/\*')
                self.comment_end = QtCore.QRegExp(r'\*/')


            for word in keywords:
                pattern = QtCore.QRegExp(r'\b' + word + r'\b')

                if lang == "Delphi": pattern.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
                self.rules.append((pattern, k_fmt))


            for word in types:
                pattern = QtCore.QRegExp(r'\b' + word + r'\b')
                if lang == "Delphi": pattern.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
                self.rules.append((pattern, t_fmt))


            if lang == "Delphi":
                self.rules.append((QtCore.QRegExp(r"'(?:[^']|'')*'"), s_fmt))
            else:
                self.rules.append((QtCore.QRegExp(r'".*"'), s_fmt))
                if lang in ["Go", "C", "C++", "C#"]:
                    self.rules.append((QtCore.QRegExp(r"'.?'"), s_fmt))
                if lang == "Python":
                     self.rules.append((QtCore.QRegExp(r"'.*'"), s_fmt))


            self.rules.append((QtCore.QRegExp(r'\b[0-9]+\b'), n_fmt))
            self.rules.append((QtCore.QRegExp(r'\b0x[0-9a-fA-F]+\b'), n_fmt))

            self.rehighlight()

        def highlightBlock(self, text):

            for pattern, format in self.rules:
                expression = QtCore.QRegExp(pattern)
                index = expression.indexIn(text)
                while index >= 0:
                    length = expression.matchedLength()
                    self.setFormat(index, length, format)
                    index = expression.indexIn(text, index + length)


            self.setCurrentBlockState(0)
            start_index = 0
            if self.previousBlockState() != 1:
                start_index = self.comment_start.indexIn(text)

            while start_index >= 0:
                end_index = self.comment_end.indexIn(text, start_index)
                comment_length = 0
                if end_index == -1:
                    self.setCurrentBlockState(1)
                    comment_length = len(text) - start_index
                else:
                    comment_length = end_index - start_index + self.comment_end.matchedLength()

                self.setFormat(start_index, comment_length, self.multiline_comment_format)
                start_index = self.comment_start.indexIn(text, start_index + comment_length)


            c_fmt = self.multiline_comment_format


            for pattern, format in self.rules:

                if format.foreground().color().name() == "#6a9955":
                     expression = QtCore.QRegExp(pattern)
                     index = expression.indexIn(text)
                     while index >= 0:
                        length = expression.matchedLength()
                        self.setFormat(index, length, format)
                        index = expression.indexIn(text, index + length)
