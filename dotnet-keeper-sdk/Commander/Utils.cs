using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Commander
{
    public static class HelperUtils
    {
        public static string ReadLineMasked(char mask = '*')
        {
            var sb = new StringBuilder();
            ConsoleKeyInfo keyInfo;
            while ((keyInfo = Console.ReadKey(true)).Key != ConsoleKey.Enter)
            {
                if (!char.IsControl(keyInfo.KeyChar))
                {
                    sb.Append(keyInfo.KeyChar);
                    Console.Write(mask);
                }
                else if (keyInfo.Key == ConsoleKey.Backspace && sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);

                    if (Console.CursorLeft == 0)
                    {
                        Console.SetCursorPosition(Console.BufferWidth - 1, Console.CursorTop - 1);
                        Console.Write(' ');
                        Console.SetCursorPosition(Console.BufferWidth - 1, Console.CursorTop - 1);
                    }
                    else Console.Write("\b \b");
                }
            }
            Console.WriteLine();
            return sb.ToString();
        }
    }

    public class Tabulate
    {
        private readonly int _columns;
        private readonly bool[] _right_align_column;
        private readonly int[] _max_chars;
        private readonly List<string[]> _data = new List<string[]>();
        public Tabulate(int columns)
        {
            _columns = columns;
            _right_align_column = Enumerable.Repeat(true, columns).ToArray();
            _max_chars = Enumerable.Repeat(0, columns).ToArray();
        }
        private string[] _header;
        public void AddHeader(IEnumerable<string> header)
        {
            _header = header.Take(_columns).ToArray();
        }

        private static bool IsNumber(object value)
        {
            return value is sbyte
                    || value is byte
                    || value is short
                    || value is ushort
                    || value is int
                    || value is uint
                    || value is long
                    || value is ulong
                    || value is float
                    || value is double
                    || value is decimal;
        }

        private static bool IsDecimal(object value)
        {
            return value is float
                    || value is double
                    || value is decimal;
        }

        public void AddRow(IEnumerable<object> fields)
        {
            var row = Enumerable.Repeat("", _columns).ToArray();
            int colNo = 0;
            foreach (var o in fields)
            {
                var text = "";
                bool isNum = false;
                if (o != null)
                {
                    text = o.ToString();
                    isNum = IsNumber(o);
                    if (isNum)
                    {
                        if (IsDecimal(o))
                        {
                            text = string.Format("{0:0.00}", o);
                        }
                    }
                }
                if (!string.IsNullOrEmpty(text))
                {
                    if (!isNum)
                    {
                        _right_align_column[colNo] = false;
                    }
                }
                row[colNo] = text;
                colNo++;
                if (colNo >= _columns)
                {
                    break;
                }
            }
            _data.Add(row);
        }

        public void SetColumnRightAlign(int colNo, bool value)
        {
            if (colNo >= 0 && colNo < _columns)
            {
                _right_align_column[colNo] = value;
            }
        }

        public void Sort(int colNo)
        {
            if (_data.Count > 1) {
                bool is_num = _right_align_column[colNo];
                if (colNo >= 0 && colNo < _columns)
                {
                    _data.Sort((x, y) =>
                    {

                        if (is_num)
                        {
                            int res = x[colNo].Length.CompareTo(y[colNo].Length);
                            if (res != 0)
                            {
                                return res;
                            }
                        }
                        return x[colNo].CompareTo(y[colNo]);
                    });
                }
            }
        }

        static readonly string RowSeparator = "  ";
        public bool DumpRowNo { get; set; }
        public int LeftPadding { get; set; }
        public int MaxColumnWidth { get; set; } = 40;

        public void Dump() {
            for (var i = 0; i < _max_chars.Length; i++)
            {
                var len = 0;
                if (DumpRowNo)
                {
                    if (i < _header.Length)
                    {
                        len = _header[i].Length;
                    }
                }
                foreach (var row in _data)
                {
                    if (i < row.Length)
                    {
                        len = Math.Max(len, row[i].Length);
                        if (len > MaxColumnWidth) {
                            len = MaxColumnWidth;
                        }
                    }
                }
                _max_chars[i] = len;
            }

            int rowNoLen = DumpRowNo ? _data.Count.ToString().Length + 1 : 0;
            if (rowNoLen > 0 && rowNoLen < 3) {
                rowNoLen = 3;
            }
            if (_header != null) {
                var r = (DumpRowNo ? (new string[] { "#".PadLeft(rowNoLen) }) : Enumerable.Empty<string>())
                    .Concat(_header.Zip(_max_chars.Zip(_right_align_column, (m, b) => b ? -m : m), (h, m) => m < 0 ? h.PadLeft(-m) : h.PadRight(m)));
                if (LeftPadding > 0) {
                    Console.Write("".PadLeft(LeftPadding));
                }
                Console.WriteLine(string.Join(RowSeparator, r));

                r = (DumpRowNo ? (new string[] { "".PadLeft(rowNoLen, '-') }) : Enumerable.Empty<string>())
                    .Concat(_max_chars.Select(m => "".PadRight(m, '-')));
                if (LeftPadding > 0)
                {
                    Console.Write("".PadLeft(LeftPadding));
                }
                Console.WriteLine(string.Join(RowSeparator, r));
            }

            int rowNo = 1;
            foreach (var row in _data) {
                var r = (DumpRowNo ? (new string[] { rowNo.ToString().PadLeft(rowNoLen) }) : Enumerable.Empty<string>())
                    .Concat(row.Zip(_max_chars.Zip(_right_align_column, (m, b) => b ? -m : m), (cell, m) => {
                        cell = cell.Replace("\n", " ");
                        if (cell.Length > MaxColumnWidth)
                        {
                            return cell.Substring(0, MaxColumnWidth - 3) + "...";
                        }
                        else {
                            if (m < 0)
                            {
                                return cell.PadLeft(-m);
                            }
                            else {
                                return cell.PadRight(m);
                            }
                        }
                    }));

                if (LeftPadding > 0)
                {
                    Console.Write("".PadLeft(LeftPadding));
                }
                Console.WriteLine(string.Join(RowSeparator, r));

                rowNo++;
            }
            Console.WriteLine();
        }
    }
}
