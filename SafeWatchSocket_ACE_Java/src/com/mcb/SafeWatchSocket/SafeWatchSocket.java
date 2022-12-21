package com.mcb.SafeWatchSocket;

import java.awt.image.ReplicateScaleFilter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore.Entry;
import java.text.Normalizer;
import java.text.Normalizer.Form;

import com.side.ofac.jswapi.SafeWatchApi;
import com.side.ofac.jswapi.SafeWatchApiCheckDetectionRequest;
import com.side.ofac.jswapi.SafeWatchApiCheckDetectionResponse;
import com.side.ofac.jswapi.SafeWatchApiLoginRequest;
import com.side.ofac.jswapi.SafeWatchApiLoginResponse;
import com.side.ofac.jswapi.SafeWatchApiReport;
import com.side.ofac.jswapi.SafeWatchApiReportEntity;
import com.side.ofac.jswapi.SafeWatchApiReportEntityAddress;
import com.side.ofac.jswapi.SafeWatchApiScanRequest;
import com.side.ofac.jswapi.SafeWatchApiScanResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.sound.sampled.AudioFormat.Encoding;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Map;
import java.util.*;
import java.util.Set;
import java.util.regex.*;

public class SafeWatchSocket {
	public static String xmlString;
	public static String value;

	public static void main(String[] args) throws UnsupportedEncodingException {
		System.out.println("Started");
		 safeWatchProcessing("10.143.4.122", "8409", "Safewatch API", "sw_apiM","pass4321", "1", "ABBAS, Amjad", "", "", "", "", "", "NAME", "", "", "", "97", "0", "0", true, false, true);
		 System.out.println("XML_Resp"+xmlString);
	//	value = CorrectData("ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖØÙÚÛÜßàáâãäåæçèéêëìíîïñòóôõöøùúûüÿabècçdééföá┤»¬ÇÄÅÉû");
	//	System.out.println(value);
	}

	public static String CorrectData(String value1) throws UnsupportedEncodingException {
		Hashtable<String, String> dictionary = new Hashtable<>();
		dictionary.put("ß", "S");
		dictionary.put("Æ", "A");
		dictionary.put("Ø", "O");
		dictionary.put("æ", "a");
		dictionary.put("ø", "o");
		dictionary.put("┤", "?");
		dictionary.put("»", "?");
		dictionary.put("¬", "?");
		Set<String> setOfKeys = dictionary.keySet();
		Iterator<String> itr = setOfKeys.iterator();
		while (itr.hasNext()) {
			String key = itr.next();
			if (value1.contains(key)) {
				value1 = value1.replace(key, dictionary.get(key));
			}
		}
		value = Normalizer.normalize(value1, Normalizer.Form.NFD).replaceAll("\\p{InCombiningDiacriticalMarks}+", "").toString();
		return value;
	}

	public static String safeWatchProcessing(String ip, String port, String fileName, String username, String password,
			String zoneId, String data, String address, String bic, String city, String context, String country,
			String format, String recordId, String recordLocation, String scanSessionId, String rank,
			String checkVessels, String checkCountry, Boolean positiveDetection, Boolean fullReport,
			Boolean autoCreateAlert) {
		SafeWatchApi Api = new SafeWatchApi();
		SafeWatchApiLoginRequest LogReq = new SafeWatchApiLoginRequest();
		SafeWatchApiLoginResponse LogResp = new SafeWatchApiLoginResponse();
		LogReq.setServerIp(ip);
		LogReq.setServerPort(Integer.parseInt(port));
		LogReq.setLoginFile(fileName);
		LogReq.setUser(username);
		LogReq.setPassword(password);
		LogReq.setZoneId(zoneId);
		// check connection
		if (Api.Login(LogReq, LogResp) != 0) {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder;
			try {
				dBuilder = dbFactory.newDocumentBuilder();
				Document doc = dBuilder.newDocument();

				Element rootElement = doc.createElement("LOGIN");
				doc.appendChild(rootElement);

				Element LastErrorCode = doc.createElement("LastErrorCode");
				rootElement.appendChild(LastErrorCode);
				LastErrorCode.appendChild(doc.createTextNode(CorrectData((Integer.toString(Api.getLastErrorCode())))));

				Element LastErrorText = doc.createElement("LastErrorText");
				rootElement.appendChild(LastErrorText);
				LastErrorText.appendChild(doc.createTextNode(CorrectData((Api.getLastErrorText()))));

				TransformerFactory transformerFactory = TransformerFactory.newInstance();
				Transformer transformer = transformerFactory.newTransformer();
				DOMSource source = new DOMSource(doc);

				StreamResult result = new StreamResult(new StringWriter());
				transformer.transform(source, result);
				xmlString = result.getWriter().toString();
				return xmlString;
			} catch (Exception e) {
			}
		} else {
			String Data = data;
			String Address = address;
			String Bic = bic;
			String City = city;
			String Context = context;
			String Country = country;
			String Format = format;
			String Recordid = recordId;
			String RecordLocation = recordLocation;
			String ScanId = scanSessionId;
			int Rank = (Integer.parseInt(rank));
			int CheckVessels = (Integer.parseInt(checkVessels));
			int CheckCountry = (Integer.parseInt(checkCountry));
			boolean Positivedetection = positiveDetection;
			boolean FullReport = fullReport;
			boolean Autocreatealert = autoCreateAlert;

			SafeWatchApiScanRequest scan = new SafeWatchApiScanRequest();
			SafeWatchApiScanResponse scanresp = new SafeWatchApiScanResponse();
			scan.reset();
			scan.setData(Data);
			scan.setAddress(Address);
			scan.setBic(Bic);
			scan.setCity(City);
			scan.setContext(Context);
			scan.setCountry(Country);
			scan.setFormat(Format);
			scan.setRecordId(Recordid);
			scan.setRecordLocation(RecordLocation);
			scan.setScanSessionId(ScanId);
			scan.setRank(Rank);
			scan.setCheckVessels(CheckVessels);
			scan.setCheckCountry(CheckCountry);
			scan.setAutoCreateAlert(Autocreatealert);
			scan.setFullReport(FullReport);
			scan.setPositiveDetection(Positivedetection);

			if (Api.Scan(scan, scanresp) != 0) {
				DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
				DocumentBuilder dBuilder;
				try {
					dBuilder = dbFactory.newDocumentBuilder();
					Document doc = dBuilder.newDocument();

					Element rootElement = doc.createElement("SCAN");
					doc.appendChild(rootElement);

					Element LastErrorCode = doc.createElement("LastErrorCode");
					rootElement.appendChild(LastErrorCode);
					LastErrorCode.appendChild(doc.createTextNode(CorrectData((Integer.toString(Api.getLastErrorCode())))));

					Element LastErrorText = doc.createElement("LastErrorText");
					rootElement.appendChild(LastErrorText);
					LastErrorText.appendChild(doc.createTextNode(CorrectData((Api.getLastErrorText()))));

					TransformerFactory transformerFactory = TransformerFactory.newInstance();
					Transformer transformer = transformerFactory.newTransformer();
					DOMSource source = new DOMSource(doc);

					StreamResult result = new StreamResult(new StringWriter());
					transformer.transform(source, result);
					xmlString = result.getWriter().toString();
					return xmlString;
				} catch (Exception e) {
				}
			} else {
				try {

					DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
					DocumentBuilder dBuilder;
					try {
						dBuilder = dbFactory.newDocumentBuilder();
						Document doc = dBuilder.newDocument();

						Element rootElement = doc.createElement("SCAN");
						doc.appendChild(rootElement);

						Element LastErrorCode = doc.createElement("LastErrorCode");
						rootElement.appendChild(LastErrorCode);
						LastErrorCode.appendChild(doc.createTextNode(CorrectData((Integer.toString(Api.getLastErrorCode())))));

						Element LastErrorText = doc.createElement("LastErrorText");
						rootElement.appendChild(LastErrorText);
						LastErrorText.appendChild(doc.createTextNode(CorrectData((Api.getLastErrorText()))));

						Element ProfileName = doc.createElement("ProfileName");
						rootElement.appendChild(ProfileName);
						// ProfileName.appendChild(doc.createTextNode(LogResp.getProfileName()));

						Element ListSetID = doc.createElement("ListSetID");
						rootElement.appendChild(ListSetID);
						try {
							ListSetID.appendChild(
									doc.createTextNode(CorrectData((Integer.toString(LogResp.getListSetID())))));
						} catch (Exception e) {
							ListSetID.appendChild(doc.createTextNode(""));
						}

						Element DetectionID = doc.createElement("DetectionID");
						rootElement.appendChild(DetectionID);
						try {
							DetectionID.appendChild(doc.createTextNode(CorrectData((Integer.toString(scanresp.getDetectionId())))));
						} catch (Exception e) {
							DetectionID.appendChild(doc.createTextNode(""));
						}

						Element AcceptCount = doc.createElement("AcceptCount");
						rootElement.appendChild(AcceptCount);
						try {
							AcceptCount.appendChild(doc.createTextNode(CorrectData((Integer.toString(scanresp.getAcceptCount())))));
						} catch (Exception e) {
							AcceptCount.appendChild(doc.createTextNode(""));
						}

						Element ExternalCount = doc.createElement("ExternalCount");
						rootElement.appendChild(ExternalCount);
						try {
							ExternalCount
									.appendChild(doc.createTextNode(CorrectData((Integer.toString(scanresp.getExternalCount())))));
						} catch (Exception e) {
							ExternalCount.appendChild(doc.createTextNode(""));
						}

						Element ViolationCount = doc.createElement("ViolationCount");
						rootElement.appendChild(ViolationCount);
						try {
							ViolationCount
									.appendChild(doc.createTextNode(CorrectData((Integer.toString((scanresp.getViolationCount()))))));
						} catch (Exception e) {
							ViolationCount.appendChild(doc.createTextNode(""));
						}
						// retrieving detection

						SafeWatchApiCheckDetectionRequest CheckDetReq = new SafeWatchApiCheckDetectionRequest();
						SafeWatchApiCheckDetectionResponse CheckDetResp = new SafeWatchApiCheckDetectionResponse();
						CheckDetReq.setDetectionId(scanresp.getDetectionId());
						Api.CheckDetection(CheckDetReq, CheckDetResp);
						if (Api.getLastErrorCode() != 0) {
							// System.out.println("CheckDetection FAILED: [" + Api.getLastErrorCode() + "] "
							// + Api.getLastErrorText());
							Element DetectionErrorCode = doc.createElement("DetectionErrorCode");
							rootElement.appendChild(DetectionErrorCode);
							Element DetectionErrorText = doc.createElement("DetectionErrorText");
							rootElement.appendChild(DetectionErrorText);
							Element GlobalStatus = doc.createElement("GlobalStatus");
							rootElement.appendChild(GlobalStatus);
							Element AlertCount = doc.createElement("AlertCount");
							rootElement.appendChild(AlertCount);
							Element rootAlerts = doc.createElement("Alerts");
							rootElement.appendChild(rootAlerts);

							CheckDetResp = null;
						} else {
							Element DetectionErrorCode = doc.createElement("DetectionErrorCode");
							rootElement.appendChild(DetectionErrorCode);
							try {
								DetectionErrorCode
										.appendChild(doc.createTextNode(CorrectData((Integer.toString(Api.getLastErrorCode())))));
							} catch (Exception e) {
								DetectionErrorCode.appendChild(doc.createTextNode(""));
							}

							Element DetectionErrorText = doc.createElement("DetectionErrorText");
							rootElement.appendChild(DetectionErrorText);
							try {
								DetectionErrorText.appendChild(doc.createTextNode(CorrectData((Api.getLastErrorText()))));
							} catch (Exception e) {
								DetectionErrorText.appendChild(doc.createTextNode(""));
							}

							Element GlobalStatus = doc.createElement("GlobalStatus");
							rootElement.appendChild(GlobalStatus);
							try {
								GlobalStatus.appendChild(doc.createTextNode(CorrectData((CheckDetResp.getGlobalStatus()))));
							} catch (Exception e) {
								GlobalStatus.appendChild(doc.createTextNode(""));
							}

							Element AlertCount = doc.createElement("AlertCount");
							rootElement.appendChild(AlertCount);
							try {
								AlertCount.appendChild(
										doc.createTextNode(CorrectData((Integer.toString(CheckDetResp.getAlertCount())))));
							} catch (Exception e) {
								AlertCount.appendChild(doc.createTextNode(""));
							}

							Element rootAlerts = doc.createElement("Alerts");
							rootElement.appendChild(rootAlerts);

							// Populate Alerts
							for (int index = 0; index < CheckDetResp.getAlertCount(); ++index) {
								Element Alert = doc.createElement("Alert");
								rootAlerts.appendChild(Alert);

								Attr attrAlertId = doc.createAttribute("AlertId");
								try {
									attrAlertId.setValue(CorrectData((Integer.toString(CheckDetResp.getAlertId(index)))));
								} catch (Exception e) {
									attrAlertId.setValue("");
								}
								Alert.setAttributeNode(attrAlertId);

								Attr attrStatus = doc.createAttribute("Status");
								try {
									attrStatus.setValue(CorrectData((CheckDetResp.getStatus(index))));
								} catch (Exception e) {
									attrStatus.setValue("");
								}
								Alert.setAttributeNode(attrStatus);
							}

							Element rootElementReports = doc.createElement("Reports");
							rootElement.appendChild(rootElementReports);

							SafeWatchApiReportEntity entity = null;
							SafeWatchApiReportEntityAddress entityAddress = null;
							SafeWatchApiReport report = null;

							for (int index = 0; index < (scanresp.getReport()).size(); ++index) {

								report = (SafeWatchApiReport) scanresp.getReport().elementAt(index);

								Element ElementReport = doc.createElement("Report");
								rootElementReports.appendChild(ElementReport);

								Element Status = doc.createElement("Status");
								ElementReport.appendChild(Status);
								try {
									Status.appendChild(doc.createTextNode(CorrectData((report.getStatus()))));
								} catch (Exception e) {
									Status.appendChild(doc.createTextNode(""));
								}

								Element Data1 = doc.createElement("Data");
								ElementReport.appendChild(Data1);
								try {
									Data1.appendChild(doc.createTextNode(CorrectData((report.getData()))));
								} catch (Exception e) {
									Data1.appendChild(doc.createTextNode(""));
								}

								Element Match = doc.createElement("Match");
								ElementReport.appendChild(Match);
								try {
									Match.appendChild(doc.createTextNode(CorrectData((report.getMatch()))));
								} catch (Exception e) {
									Match.appendChild(doc.createTextNode(""));
								}

								Element InputBIC = doc.createElement("InputBIC");
								ElementReport.appendChild(InputBIC);
								try {
									InputBIC.appendChild(doc.createTextNode(CorrectData((report.getInputBic()))));
								} catch (Exception e) {
									InputBIC.appendChild(doc.createTextNode(""));
								}

								Element InputAddress = doc.createElement("InputAddress");
								ElementReport.appendChild(InputAddress);
								try {
									InputAddress.appendChild(doc.createTextNode(CorrectData((report.getInputAddress()))));
								} catch (Exception e) {
									InputAddress.appendChild(doc.createTextNode(""));
								}

								Element InputCity = doc.createElement("InputCity");
								ElementReport.appendChild(InputCity);
								try {
									InputCity.appendChild(doc.createTextNode(CorrectData((report.getInputCity()))));
								} catch (Exception e) {
									InputCity.appendChild(doc.createTextNode(""));
								}

								Element InputCountry = doc.createElement("InputCountry");
								ElementReport.appendChild(InputCountry);
								try {
									InputCountry.appendChild(doc.createTextNode(CorrectData((report.getInputCountry()))));
								} catch (Exception e) {
									InputCountry.appendChild(doc.createTextNode(""));
								}

								Element rank1 = doc.createElement("Rank");
								ElementReport.appendChild(rank1);
								try {
									rank1.appendChild(doc.createTextNode(CorrectData((Integer.toString(report.getRank())))));
								} catch (Exception e) {
									rank1.appendChild(doc.createTextNode(""));
								}

								Element ListName = doc.createElement("ListName");
								ElementReport.appendChild(ListName);
								try {
									ListName.appendChild(doc.createTextNode(CorrectData((report.getListName()))));
								} catch (Exception e) {
									ListName.appendChild(doc.createTextNode(""));
								}

								Element ListDate = doc.createElement("ListDate");
								ElementReport.appendChild(ListDate);
								try {
									ListDate.appendChild(doc.createTextNode(CorrectData((report.getListDate()))));
								} catch (Exception e) {
									ListDate.appendChild(doc.createTextNode(""));
								}

								Element EntityId = doc.createElement("EntityId");
								ElementReport.appendChild(EntityId);
								try {
									EntityId.appendChild(doc.createTextNode(CorrectData((Integer.toString(report.getEntityId())))));
								} catch (Exception e) {
									EntityId.appendChild(doc.createTextNode(""));
								}

								Element Category = doc.createElement("Category");
								ElementReport.appendChild(Category);
								try {
									Category.appendChild(doc.createTextNode(CorrectData((report.getCategory()))));
								} catch (Exception e) {
									Category.appendChild(doc.createTextNode(""));
								}

								Element Remark = doc.createElement("Remark");
								ElementReport.appendChild(Remark);
								try {
									Remark.appendChild(doc.createTextNode(CorrectData((report.getRemark()))));
								} catch (Exception e) {
									Remark.appendChild(doc.createTextNode(""));
								}

								Element Title = doc.createElement("Title");
								ElementReport.appendChild(Title);
								try {
									Title.appendChild(doc.createTextNode(CorrectData((report.getTitle()))));
								} catch (Exception e) {
									Title.appendChild(doc.createTextNode(""));
								}

								Element BeginPosition = doc.createElement("BeginPosition");
								ElementReport.appendChild(BeginPosition);
								try {
									BeginPosition.appendChild(
											doc.createTextNode(CorrectData((Integer.toString(report.getBeginPosition())))));
								} catch (Exception e) {
									BeginPosition.appendChild(doc.createTextNode(""));
								}

								Element EndPosition = doc.createElement("EndPosition");
								ElementReport.appendChild(EndPosition);
								try {
									EndPosition
											.appendChild(doc.createTextNode(CorrectData((Integer.toString(report.getEndPosition())))));
								} catch (Exception e) {
									EndPosition.appendChild(doc.createTextNode(""));
								}

								Element Field = doc.createElement("Field");
								ElementReport.appendChild(Field);
								try {
									Field.appendChild(doc.createTextNode(CorrectData((report.getField()))));
								} catch (Exception e) {
									Field.appendChild(doc.createTextNode(""));
								}

								Element Line = doc.createElement("Line");
								ElementReport.appendChild(Line);
								try {
									Line.appendChild(doc.createTextNode(CorrectData((Integer.toString(report.getLine())))));
								} catch (Exception e) {
									Line.appendChild(doc.createTextNode(""));
								}

								Element Program = doc.createElement("Program");
								ElementReport.appendChild(Program);
								try {
									Program.appendChild(doc.createTextNode(CorrectData((report.getProgram()))));
								} catch (Exception e) {
									Program.appendChild(doc.createTextNode(""));
								}

								Element DOB = doc.createElement("DOB");
								ElementReport.appendChild(DOB);
								try {
									String strDob = report.getDOB();
									if (strDob == null) {
										throw new NullPointerException();
									} else {
										DOB.appendChild(doc.createTextNode(CorrectData((strDob))));
									}
								} catch (NullPointerException e) {
									DOB.appendChild(doc.createTextNode(""));
								}

								Element POB = doc.createElement("POB");
								ElementReport.appendChild(POB);
								try {
									String strPob = report.getPOB();
									if (strPob == null) {
										throw new NullPointerException();
									} else {
										POB.appendChild(doc.createTextNode(CorrectData((strPob))));
									}
								} catch (NullPointerException e) {
									POB.appendChild(doc.createTextNode(""));
								}

								Element ExternalId = doc.createElement("ExternalId");
								ElementReport.appendChild(ExternalId);
								ExternalId.appendChild(doc.createTextNode(CorrectData((report.getExternalId()))));

								Element elementEntities = doc.createElement("Entities");
								ElementReport.appendChild(elementEntities);

								for (int j = 0; j < report.getEntity().size(); j++) {
									entity = (SafeWatchApiReportEntity) report.getEntity().elementAt(j);

									Element Entity = doc.createElement("Entity");
									elementEntities.appendChild(Entity);

									Attr attrNameType = doc.createAttribute("NameType");
									try {
										attrNameType.setValue(CorrectData((entity.getNameType())));
									} catch (Exception e) {
										attrNameType.setValue("");
									}
									Entity.setAttributeNode(attrNameType);

									Attr attrName = doc.createAttribute("Name");
									try {
										attrName.setValue(CorrectData((entity.getName())));
									} catch (Exception e) {
										attrName.setValue("");
									}
									Entity.setAttributeNode(attrName);

								}

								Element elementAddresses = doc.createElement("Addresses");
								ElementReport.appendChild(elementAddresses);

								for (int j = 0; j < report.getEntityAddresses().size(); j++) {
									entityAddress = (SafeWatchApiReportEntityAddress) report.getEntityAddresses()
											.elementAt(j);

									Element elementAddress = doc.createElement("Address");
									elementAddresses.appendChild(elementAddress);

									Element address1 = doc.createElement("Line1");
									elementAddress.appendChild(address1);
									try {
										elementAddress.appendChild(doc.createTextNode(CorrectData((entityAddress.getAddress()))));
									} catch (Exception e) {
										elementAddress.appendChild(doc.createTextNode(""));
									}

									Element city1 = doc.createElement("City");
									elementAddress.appendChild(city1);
									try {
										elementAddress.appendChild(doc.createTextNode(CorrectData((entityAddress.getCity()))));
									} catch (Exception e) {
										elementAddress.appendChild(doc.createTextNode(""));
									}

									Element country1 = doc.createElement("Country");
									elementAddress.appendChild(country1);
									try {
										elementAddress.appendChild(doc.createTextNode(CorrectData((entityAddress.getCountry()))));
									} catch (Exception e) {
										elementAddress.appendChild(doc.createTextNode(""));
									}
								}
							}
						}

						TransformerFactory transformerFactory = TransformerFactory.newInstance();
						Transformer transformer = transformerFactory.newTransformer();
						DOMSource source = new DOMSource(doc);

						StreamResult result = new StreamResult(new StringWriter());
						transformer.transform(source, result);
						xmlString = result.getWriter().toString();
						return xmlString;
					} catch (Exception e) {
						e.printStackTrace();
					}
				}

				finally {
				}

			}

		}
		return null;

	}
}
