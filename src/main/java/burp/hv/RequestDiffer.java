package burp.hv;

import burp.IParameter;
import burp.IRequestInfo;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

public class RequestDiffer {

    public static JSONArray generateHeadersAndParametersJson(IRequestInfo[] requests) {
        JSONArray result = new JSONArray();
        if (requests == null || requests.length == 0) return result;

        boolean allIdentical = areAllRequestsIdentical(requests);

        if (allIdentical) {
            IRequestInfo lastReq = requests[requests.length - 1];
            addAllItems(result, lastReq);
        } else {
            IRequestInfo previous = null;
            for (int i = 0; i < requests.length; i++) {
                IRequestInfo current = requests[i];
                if (i == 0) {
                    addAllItems(result, current);
                } else {
                    addDifferences(result, current, previous);
                }
                previous = current;
            }
            Set<String> inAll = intersectionOfAllRequests(requests);
            result = filterNeverChangedItems(result, inAll);
        }

        return result;
    }

    private static boolean areAllRequestsIdentical(IRequestInfo[] requests) {
        for (int i = 1; i < requests.length; i++) {
            if (!requestsEquivalent(requests[0], requests[i])) return false;
        }
        return true;
    }

    private static boolean requestsEquivalent(IRequestInfo a, IRequestInfo b) {
        if (!a.getUrl().getPath().equals(b.getUrl().getPath())) return false;
        if (!a.getHeaders().equals(b.getHeaders())) return false;
        return parametersEqual(a.getParameters(), b.getParameters());
    }

    private static boolean parametersEqual(List<IParameter> listA, List<IParameter> listB) {
        if (listA.size() != listB.size()) return false;
        return parameterSet(listA).equals(parameterSet(listB));
    }

    private static Set<String> parameterSet(List<IParameter> params) {
        Set<String> set = new HashSet<>();
        for (IParameter p : params) {
            set.add(p.getType() + "|" + p.getName() + "|" + p.getValue());
        }
        return set;
    }

    private static void addAllItems(JSONArray result, IRequestInfo request) {
        for (IParameter param : request.getParameters()) {
            String type = parameterTypeText(param.getType());
            if (!type.isEmpty()) {
                JSONObject obj = new JSONObject();
                obj.put("type", type);
                obj.put("name", param.getName());
                obj.put("value", param.getValue());
                result.put(obj);
            }
        }
        String path = request.getUrl().getPath();
        if (path.length() > 1) {
            JSONObject pathObj = new JSONObject();
            pathObj.put("type", "PATH");
            pathObj.put("value", path);
            result.put(pathObj);
        }
        List<String> headers = new ArrayList<>(request.getHeaders());
        if (!headers.isEmpty()) headers.remove(0);
        for (String h : headers) {
            JSONObject headerObj = new JSONObject();
            headerObj.put("type", "header");
            headerObj.put("value", h);
            result.put(headerObj);
        }
    }

    private static void addDifferences(JSONArray result, IRequestInfo current, IRequestInfo previous) {
        String curPath = current.getUrl().getPath();
        String prevPath = previous.getUrl().getPath();
        if (!curPath.equals(prevPath)) {
            JSONObject pathObj = new JSONObject();
            pathObj.put("type", "PATH");
            pathObj.put("value", curPath);
            result.put(pathObj);
        }
        Set<String> curParams = parameterSet(current.getParameters());
        Set<String> prevParams = parameterSet(previous.getParameters());
        for (String curParam : curParams) {
            if (!prevParams.contains(curParam)) {
                String[] parts = curParam.split("\\|", 3);
                JSONObject obj = new JSONObject();
                obj.put("type", parameterTypeText(Integer.parseInt(parts[0])));
                obj.put("name", parts[1]);
                obj.put("value", parts[2]);
                result.put(obj);
            }
        }
        List<String> curHeaders = new ArrayList<>(current.getHeaders());
        List<String> prevHeaders = new ArrayList<>(previous.getHeaders());
        if (!curHeaders.isEmpty()) curHeaders.remove(0);
        if (!prevHeaders.isEmpty()) prevHeaders.remove(0);
        Set<String> curHeadersSet = new HashSet<>(curHeaders);
        Set<String> prevHeadersSet = new HashSet<>(prevHeaders);
        for (String header : curHeadersSet) {
            if (!prevHeadersSet.contains(header)) {
                JSONObject headerObj = new JSONObject();
                headerObj.put("type", "header");
                headerObj.put("value", header);
                result.put(headerObj);
            }
        }
    }

    private static String parameterTypeText(int type) {
        return switch (type) {
            case IParameter.PARAM_BODY -> "BODY";
            case IParameter.PARAM_COOKIE -> "COOKIE";
            case IParameter.PARAM_JSON -> "JSON";
            case IParameter.PARAM_URL -> "URL";
            default -> "";
        };
    }

    private static Set<String> buildRequestSet(IRequestInfo req) {
        Set<String> set = new HashSet<>();
        for (IParameter p : req.getParameters()) {
            String t = parameterTypeText(p.getType());
            if (!t.isEmpty()) {
                set.add(t + "|PARAM|" + p.getName() + "|" + p.getValue());
            }
        }
        String path = req.getUrl().getPath();
        if (path.length() > 1) {
            set.add("PATH|" + path);
        }
        List<String> headers = new ArrayList<>(req.getHeaders());
        if (!headers.isEmpty()) headers.remove(0);
        for (String h : headers) {
            set.add("header|" + h);
        }
        return set;
    }

    private static Set<String> intersectionOfAllRequests(IRequestInfo[] requests) {
        Set<String> intersection = null;
        for (IRequestInfo r : requests) {
            Set<String> current = buildRequestSet(r);
            if (intersection == null) {
                intersection = new HashSet<>(current);
            } else {
                intersection.retainAll(current);
            }
            if (intersection.isEmpty()) break;
        }
        return intersection == null ? new HashSet<>() : intersection;
    }

    private static JSONArray filterNeverChangedItems(JSONArray result, Set<String> inAll) {
        JSONArray filtered = new JSONArray();
        for (int i = 0; i < result.length(); i++) {
            JSONObject obj = result.getJSONObject(i);
            String type = obj.optString("type");
            String name = obj.optString("name", "");
            String value = obj.optString("value", "");
            String key;
            if ("header".equals(type) || "PATH".equals(type)) {
                key = type + "|" + value;
            } else {
                key = type + "|PARAM|" + name + "|" + value;
            }
            if (!inAll.contains(key)) {
                filtered.put(obj);
            }
        }
        return filtered;
    }
}
