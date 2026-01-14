from typing import Any, cast

from ..dsl.patterns import Call, MetavariableInfo, Or, Pattern


class ScalaCompiler:
    def compile(self, query: Any) -> str:
        if not query._source:
            raise ValueError("Query must have a source")

        # 1. Generate Source definition
        source_q = self.pattern_to_scala(query._source)
        if query._force_source_parameter:
            source_q = "cpg.parameter"
        if query._source_arg_index is not None and not query._force_source_parameter:
            source_q += f".argument({query._source_arg_index})"

        # 2. No steps? Just a search
        if not query._steps:
            return self.wrap_with_bindings(query, source_q)

        # 3. Handle Chained Flows
        source_q = self.wrap_sink(source_q, pattern=query._source, is_source=True)

        if len(query._steps) == 1:
            sink_base = self.pattern_to_scala(query._steps[0])
            sink_q = self.wrap_sink(sink_base, pattern=query._steps[0])
            q = f"{sink_q}.reachableByFlows({source_q})"
        else:
            # Multi-step
            current_source = source_q
            for step in query._steps[:-1]:
                step_base = self.pattern_to_scala(step)
                step_q = self.wrap_sink(step_base, pattern=step)
                current_source = f"{step_q}.where(_.reachableBy({current_source}))"

            final_sink_base = self.pattern_to_scala(query._steps[-1])
            final_sink_q = self.wrap_sink(final_sink_base, pattern=query._steps[-1])
            q = f"{final_sink_q}.reachableByFlows({current_source})"

        # 4. Sanitizers
        if query._sanitizers:
            checks = [san.to_cpg_predicate() for san in query._sanitizers]
            combined_check = " || ".join([f"{c}(e)" for c in checks])
            q += f".filter(f => !f.elements.exists(e => {combined_check}))"

        # 5. Global Metavariable Unification
        unification_filters = self.generate_unification_filters(query)
        if unification_filters:
            get_source_call_def = "val src = resolveTarget(f.elements.head)"
            get_target_def = "val target = resolveTarget(f.elements.last)"
            combined = " && ".join(unification_filters)
            q += f".filter(f => {{ {get_source_call_def}; {get_target_def}; {combined} }})"

        # 6. Final Wrapping
        return self.wrap_flow_with_bindings(query, q)

    def wrap_sink(
        self,
        p_scala: str,
        pattern: Pattern | None = None,
        is_source: bool = False,
    ) -> str:
        if is_source and "cpg.parameter" in p_scala:
            return p_scala
        if isinstance(pattern, Call) and pattern.args:
            arg_indices = ", ".join(str(i) for i in range(1, len(pattern.args) + 1))
            return (
                f"({p_scala}.flatMap(c => Iterator({arg_indices}).flatMap(i => "
                "if (c.isInstanceOf[nodes.Call] && "
                "c.asInstanceOf[nodes.Call].argument.size >= i) "
                "Iterator(c.asInstanceOf[nodes.Call].argument(i)) "
                "else Iterator.empty)))"
            )
        return (
            f"({p_scala}.flatMap(node => Iterator(node) ++ "
            f"(if (node.isInstanceOf[nodes.Call]) "
            f"node.asInstanceOf[nodes.Call].argument else Iterator.empty)))"
        )

    def wrap_flow_with_bindings(self, query: Any, flow_q: str) -> str:
        if not query._source:
            return f"{flow_q}.l"

        all_mvars: list[MetavariableInfo] = query._source._get_metavariables(
            arg_index=query._source_arg_index
        )
        for step in query._steps:
            all_mvars.extend(step._get_metavariables())

        bind_exprs = []
        source_mvars = query._source._get_metavariables(arg_index=query._source_arg_index)
        for name in query._mvar_names:
            matching_mvars = [mv for mv in all_mvars if mv["name"] == name]
            if matching_mvars:
                in_source = any(mv["name"] == name for mv in source_mvars)
                in_sink = False
                if query._steps:
                    in_sink = any(
                        mv["name"] == name for mv in query._steps[-1]._get_metavariables()
                    )

                if in_source:
                    source_occ = [mv for mv in source_mvars if mv["name"] == name][0]
                    bind_exprs.append(self.mvar_to_scala_expr("src", source_occ))
                elif in_sink:
                    match query._steps[-1]:
                        case Or() as last_step:
                            exprs = []
                            for p in last_step.patterns:
                                for m in p._get_metavariables():
                                    if m["name"] == name:
                                        pred_func = p.to_cpg_predicate()
                                        pred = f"{pred_func}(target)"
                                        val_expr = self.mvar_to_scala_expr("target", m)
                                        exprs.append((pred, val_expr))

                            if not exprs:
                                bind_exprs.append('""')
                            else:
                                combined = ""
                                for i, (pred, val) in enumerate(exprs):
                                    if i == len(exprs) - 1:
                                        combined += val
                                    else:
                                        combined += f"if ({pred}) {val} else "
                                bind_exprs.append(f"({{ {combined} }})")
                        case last_step:
                            sink_occ = [
                                mv for mv in last_step._get_metavariables() if mv["name"] == name
                            ][0]
                            bind_exprs.append(self.mvar_to_scala_expr("target", sink_occ))
                else:
                    bind_exprs.append('"<unknown>"')
            else:
                bind_exprs.append('"<unknown>"')

        get_target = "val target = resolveTarget(f.elements.last)"
        get_method = "val method = getMethodFullName(target)"
        get_src = "val src = resolveTarget(f.elements.head)"
        get_class_name = "val className = getClassName(target)"
        get_loc = "val loc = getLocation(target)"
        get_meta = "val meta = cpg.metaData.l.headOption.getOrElse(null)"

        bind_map_entries = ", ".join(
            [
                f'"{name}" -> ujson.read(write({expr}))'
                for name, expr in zip(query._mvar_names, bind_exprs)
            ]
        )

        base = f"""{flow_q}.map(f => {{
            {get_target}; {get_method}; {get_src}; {get_class_name}; {get_loc}; {get_meta};
            val res = ujson.Obj(
              "node" -> ujson.read(List(target).toJson).arr.head,
              "method" -> method,
              "src" -> ujson.read(List(src).toJson).arr.head,
              "className" -> className,
              "bindings" -> ujson.Obj({bind_map_entries}),
              "loc" -> loc,
              "metadata" -> (if (meta != null) ujson.read(List(meta).toJson).arr.head
                else ujson.Null)
            )"""

        if query._include_trace:
            base += '\n            res("trace") = f.elements.map(getLocation).l'

        base += "\n            res\n        }).distinct.l"
        return f"ujson.Arr({base}*)"

    def generate_unification_filters(self, query: Any) -> list[str]:
        if not query._source:
            return []

        filters = []
        last_step = query._steps[-1] if query._steps else None

        is_or_sink = False
        match last_step:
            case Or():
                is_or_sink = True

        for name in query._mvar_names:
            if name == "$_":
                continue

            source_occurrences = [
                m
                for m in query._source._get_metavariables(arg_index=query._source_arg_index)
                if m["name"] == name
            ]

            step_occurrences: list[dict[str, Any]] = []
            for i, step in enumerate(query._steps):
                for m in step._get_metavariables():
                    if m["name"] == name:
                        step_occurrences.append(
                            {
                                "step": step,
                                "mvar": m,
                                "is_sink": i == len(query._steps) - 1,
                            }
                        )

            if not source_occurrences and not step_occurrences:
                continue

            if is_or_sink and last_step is not None:
                intermediate_steps = [occ for occ in step_occurrences if not occ["is_sink"]]

                branch_checks = []
                # We know last_step is Or because is_or_sink is True
                for pattern in cast(Or, last_step).patterns:
                    branch_mvars = pattern._get_metavariables()
                    target_mvar = next((m for m in branch_mvars if m["name"] == name), None)
                    if target_mvar:
                        pred_func = pattern.to_cpg_predicate()
                        pred = f"{pred_func}(target)"
                        target_expr = self.mvar_to_scala_expr(
                            "target", cast(MetavariableInfo, target_mvar)
                        )
                        ref_var = "v1"
                        checks = [f"val {ref_var} = {target_expr}", f'{ref_var} != ""']
                        if source_occurrences:
                            src_expr = self.mvar_to_scala_expr(
                                "src", cast(MetavariableInfo, source_occurrences[0])
                            )
                            checks.append(self.build_ref_check(src_expr, ref_var))
                        for occ in intermediate_steps:
                            checks.append(
                                self.build_step_match(
                                    cast(Pattern, occ["step"]),
                                    cast(MetavariableInfo, occ["mvar"]),
                                    ref_var,
                                )
                            )
                        branch_checks.append((pred, f"({{ {'; '.join(checks)} }})"))

                if branch_checks:
                    combined = ""
                    for i, (pred, check) in enumerate(branch_checks):
                        if i == 0:
                            combined += f"if ({pred}) {{ {check} }}"
                        else:
                            combined += f" else if ({pred}) {{ {check} }}"
                    combined += " else true"
                    filters.append(f"({{ {combined} }})")
            else:
                sink_occurrences = [occ for occ in step_occurrences if occ["is_sink"]]
                intermediate_steps = [occ for occ in step_occurrences if not occ["is_sink"]]

                ref_expr = None
                if source_occurrences:
                    ref_expr = self.mvar_to_scala_expr(
                        "src", cast(MetavariableInfo, source_occurrences[0])
                    )
                elif sink_occurrences:
                    ref_expr = self.mvar_to_scala_expr(
                        "target", cast(MetavariableInfo, sink_occurrences[0]["mvar"])
                    )

                if not ref_expr:
                    continue

                ref_var = "v1"
                checks = [f"val {ref_var} = {ref_expr}", f'{ref_var} != ""']

                if source_occurrences and sink_occurrences:
                    target_expr = self.mvar_to_scala_expr(
                        "target", cast(MetavariableInfo, sink_occurrences[0]["mvar"])
                    )
                    checks.append(self.build_ref_check(target_expr, ref_var))

                for occ in intermediate_steps:
                    checks.append(
                        self.build_step_match(
                            cast(Pattern, occ["step"]),
                            cast(MetavariableInfo, occ["mvar"]),
                            ref_var,
                        )
                    )

                filters.append(f"({{ {'; '.join(checks)} }})")

        return filters

    def build_step_match(self, step: Pattern, mvar: MetavariableInfo, ref_var: str) -> str:
        match step:
            case Or() as or_pattern:
                branch_checks = []
                for p in or_pattern.patterns:
                    p_mvars = p._get_metavariables()
                    matching_mv = next((m for m in p_mvars if m["name"] == mvar["name"]), None)
                    pred_func = p.to_cpg_predicate()
                    if matching_mv:
                        idx = matching_mv.get("index", -1)
                        if idx is None:
                            idx = -1
                        branch_checks.append(f"unifyStep(e, {pred_func}, {ref_var}, {idx})")
                    else:
                        branch_checks.append(
                            f"((node: nodes.StoredNode) => {pred_func}(node) || "
                            f"node.start.astParent.collectAll[nodes.Call].exists({pred_func}))(e)"
                        )
                combined = " || ".join(branch_checks)
                return f"f.elements.exists(e => {combined})"
            case _:
                pred_func = step.to_cpg_predicate()
                idx = mvar.get("index", -1)
                if idx is None:
                    idx = -1
                return f"f.elements.exists(e => unifyStep(e, {pred_func}, {ref_var}, {idx}))"

    def build_ref_check(self, expr: str, ref_var: str) -> str:
        return f'({{ val v2 = {expr}; v2 != "" && {ref_var} == v2 }})'

    def mvar_to_scala_expr(self, element_var: str, mvar: MetavariableInfo) -> str:
        match mvar.get("index"):
            case int(idx):
                return f"getBinding({element_var}, {idx})"
            case _:
                return f"getBinding({element_var}, -1)"

    def wrap_with_bindings(self, query: Any, base_q: str) -> str:
        if not query._source:
            return f"{base_q}.l"

        mvars = query._source._get_metavariables()
        bind_exprs = []
        for name in query._mvar_names:
            matching = [mv for mv in mvars if mv["name"] == name]
            if matching:
                occ = matching[0]
                match occ.get("index"):
                    case int(idx):
                        bind_exprs.append(
                            f'(n.start.collectAll[nodes.Call].argument.l.lift({idx}).map(_.code).getOrElse(""))'
                        )
                    case _:
                        bind_exprs.append("getCode(n)")
            else:
                bind_exprs.append('"<unknown>"')

        get_class_name = "val className = getClassName(n)"
        get_meta = "val meta = cpg.metaData.l.headOption.getOrElse(null)"

        bind_map_entries = ", ".join(
            [
                f'"{name}" -> ujson.read(write({expr}))'
                for name, expr in zip(query._mvar_names, bind_exprs)
            ]
        )

        inner = f"""{base_q}.map(n => {{
            {get_class_name}; {get_meta};
            ujson.Obj(
              "node" -> ujson.read(List(n).toJson).arr.head,
              "method" -> getMethodFullName(n),
              "className" -> className,
              "bindings" -> ujson.Obj({bind_map_entries}),
              "loc" -> getLocation(n),
              "metadata" -> (if (meta != null) ujson.read(List(meta).toJson).arr.head
                else ujson.Null)
            )
        }}).distinct.l"""
        return f"ujson.Arr({inner}*)"

    def pattern_to_scala(self, p: Pattern) -> str:
        if hasattr(p, "to_cpg"):
            return p.to_cpg()
        return "cpg.all"


def compile_query(query: Any) -> str:
    """Compiles a Query object into a Joern Scala script."""
    return ScalaCompiler().compile(query)
