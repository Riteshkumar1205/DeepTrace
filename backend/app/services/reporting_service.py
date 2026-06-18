import os
import hashlib
from typing import Optional
from sqlmodel import Session, select
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from app.models.schemas import (
    Evidence, Case, Hashes, MetadataRecord, ForensicsResult, Upload,
    ProvenanceRecord, DeepfakeResult, AIAttributionResult, BlockchainRecord, AuditLog
)
from app.services.forensics_summary import ForensicsSummaryService
from app.services.deepfake_assessment import DeepfakeAssessmentService
from app.services.blockchain_assessment import BlockchainAssessmentService
from app.services.provenance_service import ProvenanceService
from app.services.trust_assessment import TrustAssessmentService
from app.utils.time import utc_now

class ReportingService:
    @staticmethod
    def generate_pdf_report(db: Session, evidence_id: str, output_path: str) -> bool:
        """
        Generates a professional forensic PDF report for an evidence item.
        Includes hashes, metadata, forensic results, provenance, deepfakes, AI attribution,
        blockchain anchors, and chain of custody logs.
        """
        # Fetch all records
        evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
        if not evidence:
            return False

        case = db.exec(select(Case).where(Case.id == evidence.case_id)).first()
        hashes = db.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
        metadata_record = db.exec(select(MetadataRecord).where(MetadataRecord.evidence_id == evidence_id)).first()
        forensics = db.exec(select(ForensicsResult).where(ForensicsResult.evidence_id == evidence_id)).all()
        provenance = db.exec(select(ProvenanceRecord).where(ProvenanceRecord.evidence_id == evidence_id)).first()
        deepfake = db.exec(select(DeepfakeResult).where(DeepfakeResult.evidence_id == evidence_id)).first()
        ai_attribution = db.exec(select(AIAttributionResult).where(AIAttributionResult.evidence_id == evidence_id)).first()
        blockchain = db.exec(select(BlockchainRecord).where(BlockchainRecord.evidence_id == evidence_id)).first()
        upload = db.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
        timeline = db.exec(select(AuditLog).where(AuditLog.evidence_id == evidence_id).order_by(AuditLog.timestamp)).all()
        forensics_summary = ForensicsSummaryService.build_from_records(evidence.file_type, forensics)
        deepfake_assessment = DeepfakeAssessmentService.build_from_record(evidence.file_type, deepfake)
        provenance_assessment = None
        if provenance and upload:
            provenance_assessment = ProvenanceService.assess_provenance(
                upload.storage_path,
                metadata={
                    "creator": provenance.creator,
                    "device": provenance.device,
                    "editing_history": provenance.editing_history,
                },
                blockchain_verified=bool(blockchain),
            )
        blockchain_assessment = BlockchainAssessmentService.build(
            blockchain,
            evidence_hash=hashes.sha256 if hashes else None,
            provenance_assessment=provenance_assessment,
            trust_score=evidence.trust_score,
        )
        trust_assessment = TrustAssessmentService.build(db, evidence_id)

        # Document setup
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=54,
            leftMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        
        # Premium Palette colors
        primary_color = colors.HexColor("#312E81")  # Indigo 900
        secondary_color = colors.HexColor("#4F46E5")  # Indigo 600
        dark_neutral = colors.HexColor("#111827")  # Gray 900
        light_neutral = colors.HexColor("#F3F4F6")  # Gray 100
        accent_red = colors.HexColor("#E11D48")  # Rose 600
        accent_green = colors.HexColor("#059669")  # Emerald 600

        # Styles
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=24,
            leading=28,
            textColor=primary_color,
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=secondary_color,
            fontName='Helvetica-Bold',
            spaceAfter=20
        )
        h1_style = ParagraphStyle(
            'ReportH1',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=primary_color,
            spaceBefore=14,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontSize=9,
            leading=13,
            textColor=dark_neutral,
            spaceAfter=6
        )
        bold_body_style = ParagraphStyle(
            'ReportBoldBody',
            parent=body_style,
            fontName='Helvetica-Bold'
        )
        code_style = ParagraphStyle(
            'ReportCode',
            parent=styles['Code'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1F2937"),
            spaceAfter=4
        )

        story = []

        # --- HEADER BLOCK ---
        story.append(Paragraph("DEEPTRACE AI", title_style))
        story.append(Paragraph("Unified Cyber Forensics, Provenance & Trust Intelligence Platform", subtitle_style))
        story.append(Spacer(1, 10))

        # --- CASE & EVIDENCE METADATA ---
        metadata_table_data = [
            [
                Paragraph("<b>CASE DETAILS</b>", bold_body_style),
                Paragraph("<b>EVIDENCE DETAILS</b>", bold_body_style)
            ],
            [
                Paragraph(f"<b>Case Number:</b> {case.case_number if case else 'N/A'}", body_style),
                Paragraph(f"<b>File Name:</b> {evidence.filename}", body_style)
            ],
            [
                Paragraph(f"<b>Title:</b> {case.title if case else 'N/A'}", body_style),
                Paragraph(f"<b>File Type:</b> {evidence.file_type.upper()}", body_style)
            ],
            [
                Paragraph(f"<b>Status:</b> {evidence.status.upper()}", body_style),
                Paragraph(f"<b>MIME Type:</b> {evidence.mime_type}", body_style)
            ],
            [
                Paragraph(f"<b>Acquisition Date:</b> {evidence.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style),
                Paragraph(f"<b>File Size:</b> {evidence.size_bytes} Bytes", body_style)
            ],
            [
                Paragraph(f"<b>Trust Score Snapshot:</b> {evidence.trust_score:.1f}%", body_style),
                Paragraph(f"<b>Forensic Risk Level:</b> {evidence.risk_level}", body_style)
            ]
        ]
        
        meta_table = Table(metadata_table_data, colWidths=[250, 250])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), primary_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('LINEBELOW', (0,0), (-1,0), 2, secondary_color),
            ('BACKGROUND', (0,1), (-1,-1), light_neutral),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
        ]))
        
        # Color coding title cells in metadata table
        for r_idx in range(len(metadata_table_data)):
            if r_idx == 0:
                meta_table.setStyle(TableStyle([('TEXTCOLOR', (0,r_idx), (-1,r_idx), colors.white)]))
        
        story.append(meta_table)
        story.append(Spacer(1, 15))

        # --- DIGITAL FINGERPRINTS ---
        story.append(Paragraph("Cryptographic Fingerprints & Perceptual Hashes", h1_style))
        fingerprint_data = [
            [Paragraph("<b>Algorithm</b>", bold_body_style), Paragraph("<b>Hash Value / Signature</b>", bold_body_style)],
            [Paragraph("SHA256", bold_body_style), Paragraph(hashes.sha256 if hashes else "N/A", code_style)],
            [Paragraph("MD5", bold_body_style), Paragraph(hashes.md5 if hashes else "N/A", code_style)],
            [Paragraph("SHA512", bold_body_style), Paragraph(hashes.sha512 if hashes else "N/A", code_style)]
        ]
        if hashes and hashes.p_hash:
            fingerprint_data.append([Paragraph("Perceptual pHash", bold_body_style), Paragraph(hashes.p_hash, code_style)])
        
        fp_table = Table(fingerprint_data, colWidths=[120, 380])
        fp_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), secondary_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, light_neutral]),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(fp_table)
        story.append(Spacer(1, 15))

        # --- FORENSIC RESULTS ---
        if forensics:
            story.append(Paragraph("Deep Forensic Analysis Results", h1_style))
            forensics_data = [
                [
                    Paragraph("<b>Engine / Probe</b>", bold_body_style),
                    Paragraph("<b>Status</b>", bold_body_style),
                    Paragraph("<b>Confidence</b>", bold_body_style),
                    Paragraph("<b>Details / Findings</b>", bold_body_style)
                ]
            ]
            for f in forensics:
                status_text = "ANOMALY DETECTED" if f.tampered else "VERIFIED AUTHENTIC"
                status_color = accent_red if f.tampered else accent_green
                status_para = Paragraph(f"<font color='{status_color.hexval()}'><b>{status_text}</b></font>", bold_body_style)
                
                reasons = ""
                if f.output_details and "reasons" in f.output_details:
                    reasons = "; ".join(f.output_details["reasons"])
                elif f.output_details and "reasons" in f.output_details.get("structure", {}):
                    reasons = "; ".join(f.output_details["structure"]["reasons"])
                else:
                    reasons = "Scan completed successfully."

                forensics_data.append([
                    Paragraph(f.engine_name, bold_body_style),
                    status_para,
                    Paragraph(f"{f.confidence:.1f}%", body_style),
                    Paragraph(reasons, body_style)
                ])

            forensics_table = Table(forensics_data, colWidths=[120, 110, 70, 200])
            forensics_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), secondary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, light_neutral]),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('TOPPADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(forensics_table)
            story.append(Spacer(1, 15))

        if forensics_summary:
            story.append(Paragraph("Unified Forensics Summary", h1_style))
            summary_data = [
                [Paragraph("<b>File Type</b>", bold_body_style), Paragraph(forensics_summary.get("file_type", "N/A"), body_style)],
                [Paragraph("<b>Verdict</b>", bold_body_style), Paragraph("TAMPERED" if forensics_summary.get("tampered") else "CLEAN", body_style)],
                [Paragraph("<b>Confidence Score</b>", bold_body_style), Paragraph(f"{forensics_summary.get('confidence_score', 0.0):.1f}%", body_style)],
                [Paragraph("<b>Verification Method</b>", bold_body_style), Paragraph(forensics_summary.get("verification_method", "N/A"), body_style)],
                [Paragraph("<b>Supporting Evidence</b>", bold_body_style), Paragraph("; ".join(forensics_summary.get("supporting_evidence", [])) or "N/A", body_style)]
            ]

            if forensics_summary.get("modified_regions"):
                summary_data.append([
                    Paragraph("<b>Modified Regions</b>", bold_body_style),
                    Paragraph(", ".join(forensics_summary.get("modified_regions", [])), body_style),
                ])

            summary_table = Table(summary_data, colWidths=[150, 350])
            summary_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, light_neutral]),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 15))

        # --- DEEPFAKE & AI ATTRIBUTION ---
        if deepfake or ai_attribution:
            story.append(Paragraph("Artificial Generation & Deepfake Forensics", h1_style))
            ai_data = []
            
            if deepfake and deepfake_assessment:
                df_risk = deepfake_assessment["risk_level"]
                ai_data.append([
                    Paragraph("<b>Deepfake Detection Model:</b>", bold_body_style),
                    Paragraph(
                        f"{deepfake.model_name} (Prob: {deepfake.deepfake_probability * 100:.1f}% • {df_risk})",
                        body_style,
                    )
                ])
                if deepfake_assessment.get("supporting_evidence"):
                    ai_data.append([
                        Paragraph("<b>Deepfake Assessment:</b>", bold_body_style),
                        Paragraph("; ".join(deepfake_assessment["supporting_evidence"]), body_style)
                    ])
                if deepfake_assessment.get("heatmap_available"):
                    ai_data.append([
                        Paragraph("<b>Explainability Heatmap:</b>", bold_body_style),
                        Paragraph("Heatmap generated and available for review.", body_style)
                    ])

            if ai_attribution:
                ai_data.append([
                    Paragraph("<b>AI Generator Origin:</b>", bold_body_style),
                    Paragraph(f"{ai_attribution.predicted_source} (Attribution Conf: {ai_attribution.confidence:.1f}%)", body_style)
                ])
                if ai_attribution.indicators and "metadata_signals" in ai_attribution.indicators:
                    sigs = ", ".join(ai_attribution.indicators["metadata_signals"])
                    ai_data.append([
                        Paragraph("<b>Fingerprints Extracted:</b>", bold_body_style),
                        Paragraph(sigs, body_style)
                    ])

            ai_table = Table(ai_data, colWidths=[150, 350])
            ai_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, light_neutral]),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(ai_table)
            story.append(Spacer(1, 15))

        # --- DIGITAL PROVENANCE (C2PA) ---
        if provenance and provenance.has_manifest:
            story.append(Paragraph("Content Credentials Provenance (C2PA / JUMBF)", h1_style))
            prov_status = "VERIFIED CONTENT CREDENTIALS" if provenance.manifest_valid else "TAMPERED/UNTRUSTED MANIFEST"
            prov_color = accent_green if provenance.manifest_valid else accent_red

            prov_data = [
                [Paragraph("<b>Validation Status:</b>", bold_body_style), Paragraph(f"<font color='{prov_color.hexval()}'><b>{prov_status}</b></font>", bold_body_style)],
                [Paragraph("<b>Claim Asserted By:</b>", bold_body_style), Paragraph(provenance.creator or "Unknown Creator", body_style)],
                [Paragraph("<b>Acquisition Device:</b>", bold_body_style), Paragraph(provenance.device or "Unknown Capture Device", body_style)],
                [Paragraph("<b>Verification Authority:</b>", bold_body_style), Paragraph(provenance.verification_method, body_style)]
            ]
            
            prov_table = Table(prov_data, colWidths=[150, 350])
            prov_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, light_neutral]),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(prov_table)
            story.append(Spacer(1, 15))

        # --- BLOCKCHAIN CUSTODY SEAL ---
        if blockchain:
            story.append(Paragraph("Blockchain Ledger Custody Proof", h1_style))
            bc_data = [
                [Paragraph("<b>Anchor Network:</b>", bold_body_style), Paragraph(blockchain.chain_name, body_style)],
                [Paragraph("<b>Block Confirmation:</b>", bold_body_style), Paragraph(f"Block #{blockchain.block_number}", body_style)],
                [Paragraph("<b>Transaction Hash:</b>", bold_body_style), Paragraph(blockchain.transaction_hash, code_style)],
                [Paragraph("<b>Registered Owner Cert:</b>", bold_body_style), Paragraph(blockchain.registered_owner, code_style)],
                [Paragraph("<b>Registry Timestamp:</b>", bold_body_style), Paragraph(blockchain.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'), body_style)]
            ]
            bc_table = Table(bc_data, colWidths=[150, 350])
            bc_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#EEF2F6")),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#6366F1")), # Purple-ish border
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(bc_table)
            story.append(Spacer(1, 15))

        if blockchain_assessment and blockchain_assessment.get("anchored"):
            story.append(Paragraph("Blockchain Assessment", h1_style))
            bc_assessment_data = [
                [Paragraph("<b>Ownership Classification:</b>", bold_body_style), Paragraph(blockchain_assessment["ownership_classification"], body_style)],
                [Paragraph("<b>Confidence Score:</b>", bold_body_style), Paragraph(f"{blockchain_assessment['confidence_score']:.1f}%", body_style)],
                [Paragraph("<b>Anchor Strength:</b>", bold_body_style), Paragraph(f"{blockchain_assessment['anchor_strength']:.1f}%", body_style)],
                [Paragraph("<b>Verification Method:</b>", bold_body_style), Paragraph(blockchain_assessment["verification_method"], body_style)],
                [Paragraph("<b>Supporting Evidence:</b>", bold_body_style), Paragraph("; ".join(blockchain_assessment["supporting_evidence"]), body_style)],
            ]
            bc_assessment_table = Table(bc_assessment_data, colWidths=[150, 350])
            bc_assessment_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, light_neutral]),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(bc_assessment_table)
            story.append(Spacer(1, 15))

        if trust_assessment:
            story.append(Paragraph("Trust Intelligence Assessment", h1_style))
            trust_data = [
                [Paragraph("<b>Verdict</b>", bold_body_style), Paragraph(trust_assessment["verdict"], body_style)],
                [Paragraph("<b>Trust Band</b>", bold_body_style), Paragraph(trust_assessment["trust_band"], body_style)],
                [Paragraph("<b>Risk Level</b>", bold_body_style), Paragraph(trust_assessment["risk_level"], body_style)],
                [Paragraph("<b>Confidence Score</b>", bold_body_style), Paragraph(f"{trust_assessment['confidence_score']:.1f}%", body_style)],
                [Paragraph("<b>Stability</b>", bold_body_style), Paragraph(trust_assessment["stability"], body_style)],
                [Paragraph("<b>Verification Methods</b>", bold_body_style), Paragraph("; ".join(trust_assessment.get("verification_methods", [])), body_style)],
                [Paragraph("<b>Supporting Evidence</b>", bold_body_style), Paragraph("; ".join(trust_assessment.get("supporting_evidence", [])), body_style)],
                [Paragraph("<b>Recommendations</b>", bold_body_style), Paragraph("; ".join(trust_assessment.get("recommendations", [])), body_style)],
            ]
            trust_table = Table(trust_data, colWidths=[150, 350])
            trust_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, light_neutral]),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(trust_table)
            story.append(Spacer(1, 15))

        # --- CHAIN OF CUSTODY AUDIT LOGS ---
        if timeline:
            story.append(Paragraph("Chain of Custody Audit Log", h1_style))
            timeline_data = [
                [
                    Paragraph("<b>Timestamp (UTC)</b>", bold_body_style),
                    Paragraph("<b>Actor</b>", bold_body_style),
                    Paragraph("<b>Operation</b>", bold_body_style),
                    Paragraph("<b>Audit Result Status</b>", bold_body_style)
                ]
            ]
            for log in timeline:
                timeline_data.append([
                    Paragraph(log.timestamp.strftime('%Y-%m-%d %H:%M:%S'), body_style),
                    Paragraph(log.actor, body_style),
                    Paragraph(log.operation, body_style),
                    Paragraph(log.result, body_style)
                ])

            timeline_table = Table(timeline_data, colWidths=[110, 130, 130, 130])
            timeline_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), primary_color),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, light_neutral]),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(KeepTogether([timeline_table]))
            story.append(Spacer(1, 20))

        # --- SIGNATURE BLOCK ---
        report_sig = hashlib.sha256(f"report-{evidence_id}-signed-by-deeptrace-at-{utc_now().timestamp()}".encode()).hexdigest()
        sig_data = [
            [
                Paragraph("<b>Platform Autogenerated Seal:</b>", bold_body_style),
                Paragraph(f"DEEPTRACE-SECURE-FORENSIC-REPORT-SHA256: {report_sig}", code_style)
            ]
        ]
        sig_table = Table(sig_data, colWidths=[150, 350])
        sig_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), light_neutral),
            ('BOX', (0,0), (-1,-1), 1.5, primary_color),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(KeepTogether([sig_table]))

        # Build Document
        doc.build(story)
        return True
