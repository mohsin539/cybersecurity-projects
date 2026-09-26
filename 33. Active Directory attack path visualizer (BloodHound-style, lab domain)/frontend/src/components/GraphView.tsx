import { useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import type { GraphData } from '../api'

cytoscape.use(dagre)

const KIND_COLOR: Record<string, string> = {
  user: '#22d3ee', group: '#a78bfa', computer: '#34d399',
  domain: '#f59e0b', gpo: '#f472b6', ou: '#94a3b8', container: '#64748b',
  ca: '#ef4444', cert_template: '#fb923c',
}
const KIND_SIZE: Record<string, number> = {
  domain: 46, user: 26, group: 30, computer: 28, gpo: 22, ou: 20, container: 16,
  ca: 38, cert_template: 24,
}
const EDGE_COLOR: Record<string, string> = {
  dcsync: '#f43f5e', generic_all: '#fb7185', owns: '#fb7185',
  write_dacl: '#f97316', write_owner: '#f97316',
  all_extended_rights: '#eab308', generic_write: '#eab308',
  force_change_pw: '#f97316', add_member: '#eab308',
  allowed_to_delegate: '#c084fc', admin_on: '#ef4444',
  rdp_on: '#a3a3a3', member_of: '#334155', has_session: '#155e75',
  gplink: '#1e3a5f',
  enroll: '#fb923c', autoenroll: '#f59e0b',
  manage_certificates: '#fbbf24', manage_ca: '#f43f5e',
  published_on: '#334155',
}

export default function GraphView(props: {
  data: GraphData
  pathNodes?: Set<string>
  onSelect: (id: string) => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const { data, pathNodes, onSelect } = props

  useEffect(() => {
    if (!ref.current) return
    const elements = [
      ...data.nodes.map(n => ({
        data: {
          id: n.id, label: n.label.replace(/^CORPLAB\\\\/, ''),
          kind: n.kind, tier: n.tier,
          color: KIND_COLOR[n.kind] ?? '#64748b',
          size: KIND_SIZE[n.kind] ?? 20,
        },
      })),
      ...data.edges.map((e, i) => ({
        data: {
          id: `e${i}`, source: e.source, target: e.target,
          kind: e.kind, color: EDGE_COLOR[e.kind] ?? '#1e293b',
        },
      })),
    ]

    const cy = cytoscape({
      container: ref.current,
      elements,
      style: [
        { selector: 'node', style: {
          'background-color': 'data(color)',
          label: 'data(label)',
          color: '#cbd5e1',
          'font-size': 9,
          'text-valign': 'bottom',
          'text-margin-y': 4,
          width: 'data(size)',
          height: 'data(size)',
          'border-width': 1.5,
          'border-color': '#0a0f1c',
        } as cytoscape.Css.Node },
        { selector: 'node[tier = 0]', style: {
          'border-width': 2.5,
          'border-color': '#f59e0b',
          'shadow-blur': 18, 'shadow-color': '#f59e0b', 'shadow-opacity': 0.5,
        } as unknown as cytoscape.Css.Node },
        { selector: 'edge', style: {
          width: 1.4,
          'curve-style': 'bezier',
          'line-color': 'data(color)',
          'target-arrow-color': 'data(color)',
          'target-arrow-shape': 'triangle',
          opacity: 0.55,
        } as cytoscape.Css.Edge },
        { selector: 'node.highlighted', style: {
          'border-width': 3, 'border-color': '#22d3ee',
        } as cytoscape.Css.Node },
        { selector: 'edge.highlighted', style: {
          width: 3, opacity: 1,
        } as cytoscape.Css.Edge },
      ],
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: 26, rankSep: 70,
                animate: false } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.25,
    })

    cy.on('tap', 'node', evt => onSelect(evt.target.id()))
    cy.nodes().lock()
    cyRef.current = cy
    // Automation/debug handle (E2E uses it to select canvas nodes).
    ;(window as unknown as { __sg_cy?: cytoscape.Core }).__sg_cy = cy
    const ro = new ResizeObserver(() => cy.resize())
    ro.observe(ref.current)
    return () => { ro.disconnect(); cy.destroy() }
  }, [data, onSelect])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().removeClass('highlighted')
    cy.edges().removeClass('highlighted')
    if (!pathNodes || pathNodes.size === 0) return
    cy.nodes().forEach(n => { if (pathNodes.has(n.id())) n.addClass('highlighted') })
    // highlight edges fully inside the path
    cy.edges().forEach(e => {
      if (pathNodes.has(e.source().id()) && pathNodes.has(e.target().id()))
        e.addClass('highlighted')
    })
  }, [pathNodes])

  return <div ref={ref} className="h-full w-full" />
}
