package burp;

public interface IResponseVariations {
    int getVariantCount();
    int getInvariantCount();
    int getCommonWordsCount();
    int getAttributeValue(int attributeType, int itemIndex);
    byte[] getAttributeValue(int attributeType, int itemIndex, int valueIndex);
    void updateWith(byte[]... responses);
}