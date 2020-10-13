#!/usr/bin/python3

import z3

class Nonogram:
  def __init__(self, columns, rows):
    self.columns = columns
    self.rows = rows
    self.solver = z3.Solver()

    self.xsize = len(columns)
    self.ysize = len(rows)

  def get_answer(self):
    answer = []
    for y in range(self.ysize):
      line = []
      for x in range(self.xsize):
        v = self.model.evaluate(self.cells[y][x])
        if str(v) == "True":
          line.append(1)
        else:
          line.append(0)
      answer.append(line)
    return answer


  def get_all_answers(self):
    if self.solver.check() == z3.sat:
      self.model = self.solver.model()
      return self.get_answer()
      current_solution = []
      for v in self.model:
        current_solution.append(v() != self.model[v])
      self.solver.add(z3.Or(current_solution))
      if self.solver.check() == z3.sat:
        print("solution is not unique")
      else:
        print("solution is unique")
    else:
      print("failed to solve")

  def setup_vars(self, nums, prefix, size):
    results = []
    for i in range(len(nums)):
      vs = z3.Int("%s,%d,s" % (prefix, i+1))
      ve = z3.Int("%s,%d,e" % (prefix, i+1))
      self.solver.add(ve-vs == nums[i]-1)
      self.solver.add(vs >= 0)
      self.solver.add(ve < size)
      results.append((vs,ve))

    for i in range(len(nums)-1):
      ve0 = results[i][1]
      vs1 = results[i+1][0]
      self.solver.add(vs1 >= ve0+2)

    return results

  def setup_cell_constraints(self, cells, cvars):
    for i in range(len(cells)):
      rule_i = z3.Or([z3.And(vs <= i, i <= ve) for (vs,ve) in cvars])
      self.solver.add(cells[i] == rule_i)

  def solve(self):
    self.cells = [[z3.Bool("cell[%d,%d]" % (x+1,y+1)) for x in range(self.xsize)] for y in range(self.ysize)]

    self.column_vars = [
      self.setup_vars(self.columns[i], "c%d" % (i+1), self.ysize)
      for i in range(self.xsize)
    ]
    self.row_vars = [
      self.setup_vars(self.rows[i], "r%d" % (i+1), self.xsize)
      for i in range(self.ysize)
    ]

    for i in range(self.xsize):
      self.setup_cell_constraints([row[i] for row in self.cells], self.column_vars[i])

    for i in range(self.ysize):
      self.setup_cell_constraints(self.cells[i], self.row_vars[i])

    return self.get_all_answers()

if __name__ == '__main__':
    nonogram = Nonogram(
      [
        [2],
        [1,2],
        [2,3],
        [2,3],
        [3,1,1],
        [2,1,1],
        [1,1,1,2,2],
        [1,1,3,1,3],
        [2,6,4],
        [3,3,9,1],
        [5,3,2],
        [3,1,2,2],
        [2,1,7],
        [3,3,2],
        [2,4],
        [2,1,2],
        [2,2,1],
        [2,2],
        [1],
        [1],
      ],
      [
        [3],
        [5],
        [3,1],
        [2,1],
        [3,3,4],
        [2,2,7],
        [6,1,1],
        [4,2,2],
        [1,1],
        [3,1],
        [6],
        [2,7],
        [6,3,1],
        [1,2,2,1,1],
        [4,1,1,3],
        [4,2,2],
        [3,3,1],
        [3,3],
        [3],
        [2,1],
      ]
    )

    print(nonogram.solve())
